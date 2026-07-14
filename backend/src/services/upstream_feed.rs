//! Upstream change-feed subscriptions for proxy repositories (#2249).
//!
//! A proxy can only bound metadata staleness with TTLs unless the upstream
//! says when packages change. Some upstreams do: npm publishes a public
//! replication feed (`replicate.npmjs.com/_changes`) streaming package-change
//! events. That endpoint answers to a CouchDB-*shaped* `_changes` document but
//! is not CouchDB — it self-identifies as `engine: npm-replicate` and rejects
//! the CouchDB long-poll controls (`feed=`, `timeout=`, `since=now`) with 400.
//! It supports only a plain numeric `since` cursor plus `limit`. This module is
//! a small, generic subscription framework over such feeds:
//!
//! * [`UpstreamFeedAdapter`] — per-ecosystem driver turning one upstream feed
//!   into a normalised stream of [`FeedEvent`]s. First implementation:
//!   [`NpmReplicationFeedAdapter`], which polls `_changes?since=<n>&limit=<n>`,
//!   resuming from the last sequence number and bootstrapping the head cursor
//!   from the feed root's `update_seq` on first enablement.
//! * [`FeedAction`] — pluggable per-event action. Default:
//!   [`PackumentInvalidationAction`], which drops the cached computed
//!   packuments for the changed package in every remote npm repository
//!   proxying the feed's upstream (and every virtual repo containing one).
//! * [`FeedConsumer`] — the runner: cluster-wide single consumer via the
//!   existing advisory-lock primitive (so N replicas do not open N feed
//!   connections), resume cursor persisted in `upstream_feed_state`
//!   (migration 156), reconnect with capped exponential backoff.
//!
//! Best-effort by design: the feed is a freshness optimisation, never the
//! correctness mechanism — the packument cache's TTL/stale-while-revalidate
//! windows remain the staleness floor if the feed is down, re-shaped, or
//! events are missed. Actions must therefore be idempotent; a dual-consumer
//! overlap after a leader's lock connection silently dies is harmless and
//! bounded by the leadership term (leaders step down and re-contend).
//!
//! Cross-replica note: with the shared (Redis) packument-cache backend an
//! invalidation issued by the consumer propagates to every replica; with the
//! in-process backend it clears the consumer's replica only and the other
//! replicas fall back to the TTL floor.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use serde::Deserialize;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::config::Config;
use crate::error::{AppError, Result};
use crate::services::cluster_lock::{lease_object_id, ClusterLock, PgAdvisoryLock};
use crate::services::npm_packument_cache::{self, NpmPackumentCache};

/// Advisory-lock class for upstream-feed consumers. Distinct from
/// `PROXY_HYDRATION_LOCK_CLASS` (0x1609) and the scheduler locks
/// (9001-9099), so feed leadership can never collide with other
/// application locks.
pub const UPSTREAM_FEED_LOCK_CLASS: i32 = 0x2249;

/// Default endpoint of npm's public replication feed.
pub const NPM_REPLICATION_FEED_DEFAULT_URL: &str = "https://replicate.npmjs.com/_changes";

/// Hosts whose packages the public npm replication feed describes. Remote
/// repositories with any other upstream (private registries, mirrors with
/// their own namespaces) are out of the feed's scope and must not be
/// invalidated by it.
const NPM_PUBLIC_REGISTRY_HOSTS: &[&str] = &["registry.npmjs.org", "registry.npmjs.com"];

/// Client-side bound per request. The feed answers immediately (no long-poll),
/// so this only needs to cover connect + a small body; a black-holed feed
/// cannot hang the consumer loop past it.
const NPM_FEED_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Cap on change rows per poll, bounding memory and per-batch work. Also the
/// signal for backlog draining: a batch that returns this many rows is treated
/// as "full" (more likely waiting), so the consumer re-polls immediately
/// instead of pacing.
const NPM_FEED_BATCH_LIMIT: u32 = 200;

/// Ceiling on a feed/bootstrap response body. The feed answers with tiny JSON
/// (a `limit`-bounded row list, or the root's counters), but `bytes_stream()`
/// is otherwise unbounded — AK has been OOM'd before by an unbounded upstream
/// metadata body (#1607/#1608), so cap generously and error over it rather
/// than buffer without limit.
const FEED_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Idle-poll cadence for the npm adapter: with no server-side long-poll, an
/// empty answer must be paced or the consumer would poll npm at ~1 Hz forever.
const NPM_FEED_IDLE_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Default idle-poll cadence for adapters that don't override it. Matches the
/// original 1 s empty-batch pacing, so a future true-long-poll adapter (which
/// blocks server-side and rarely returns instantly) keeps the old behaviour.
const DEFAULT_IDLE_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Backoff bounds for feed poll failures.
const FEED_BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const FEED_BACKOFF_MAX: Duration = Duration::from_secs(60);

/// How often a non-leader replica re-checks whether it should take over the
/// subscription.
const LEADER_RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// Upper bound on one uninterrupted leadership stint: the leader steps
/// down, releases the lock and re-contends. A Postgres session lock is
/// freed server-side when its (detached) connection dies, and the holder
/// has no way to notice — without a bounded term that silent loss would
/// leave the old leader consuming alongside its successor until process
/// restart. The term bounds any such overlap; actions are idempotent, so
/// the overlap is harmless while it lasts.
const LEADER_TERM: Duration = Duration::from_secs(300);

/// A normalised package-change event from an upstream feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedEvent {
    pub package: String,
}

/// One polled batch plus the resume cursor observed at its end.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FeedBatch {
    pub events: Vec<FeedEvent>,
    /// Opaque resume cursor; `None` when the feed did not advance it.
    pub last_seq: Option<String>,
    /// The poll came back at the adapter's row limit, so more changes are
    /// almost certainly waiting. The consumer re-polls such a batch
    /// immediately (backlog drain) instead of pacing to the idle interval.
    pub batch_was_full: bool,
}

/// Ecosystem-specific driver turning one upstream change feed into
/// normalised [`FeedBatch`]es.
#[async_trait]
pub trait UpstreamFeedAdapter: Send + Sync {
    /// Stable identity for leadership locking and resume-state keying.
    fn feed_key(&self) -> &str;
    /// The cursor to start from when no cursor has been persisted yet.
    ///
    /// Feeds whose bare start is their genesis MUST resolve a head cursor here
    /// and return `Err` if they cannot: replaying an upstream's full change
    /// history on first enablement would invalidate live cache entries for
    /// hours while delivering no freshness benefit. `Ok(None)` is reserved for
    /// adapters where polling from an absent cursor is *itself* safe (e.g. a
    /// true long-poll that begins at the head); the consumer treats `Err` like
    /// an unreadable persisted cursor — back off and retry, never genesis.
    ///
    /// This is async (unlike a static sentinel) because head discovery is a
    /// network round-trip for feeds like npm-replicate, which dropped
    /// CouchDB's `since=now`.
    async fn bootstrap_cursor(&self) -> Result<Option<String>> {
        Ok(None)
    }
    /// How long to wait after a partial/empty poll before polling again. Feeds
    /// with no server-side long-poll answer instantly, so without pacing the
    /// consumer would hot-loop; adapters that block server-side can keep the
    /// [`DEFAULT_IDLE_POLL_INTERVAL`].
    fn idle_poll_interval(&self) -> Duration {
        DEFAULT_IDLE_POLL_INTERVAL
    }
    /// Run one poll round, resuming after `since` when provided. An empty
    /// batch is a normal outcome (no changes since the cursor), not an error.
    async fn poll(&self, since: Option<&str>) -> Result<FeedBatch>;
}

/// Action applied to each polled batch of events. Must be idempotent: the
/// feed is best-effort, so an action may observe duplicate or missed events.
/// Batch-shaped so implementations can amortise per-batch work (the default
/// invalidation action resolves the repository set once per batch, not once
/// per event).
#[async_trait]
pub trait FeedAction: Send + Sync {
    /// Returns whether the batch was applied. On `false` the consumer must
    /// not advance the cursor past these events, so a later attempt (or
    /// leader) replays them instead of losing them.
    async fn apply(&self, events: &[FeedEvent]) -> bool;
}

/// Resume-cursor persistence seam (table `upstream_feed_state`).
#[async_trait]
pub trait FeedStateStore: Send + Sync {
    async fn load(&self, feed_key: &str) -> Result<Option<String>>;
    async fn save(&self, feed_key: &str, last_seq: &str) -> Result<()>;
}

/// Double-and-cap backoff step.
fn next_backoff(current: Duration, max: Duration) -> Duration {
    (current * 2).min(max)
}

/// Log level for a persistent-failure event, by consecutive-failure count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FeedLogLevel {
    Debug,
    Warn,
}

/// A transient blip should not spam warnings, but a feed that fails forever
/// must be visible. Keep the first two consecutive failures at debug, escalate
/// the 3rd to warn, then re-warn roughly every 10th so a permanently-broken
/// feed stays in the logs without flooding them.
fn failure_log_level(consecutive: u32) -> FeedLogLevel {
    if consecutive == 3 || (consecutive > 3 && consecutive % 10 == 0) {
        FeedLogLevel::Warn
    } else {
        FeedLogLevel::Debug
    }
}

/// Log one feed failure at the level [`failure_log_level`] dictates, carrying
/// the consecutive count so an operator can see a feed is stuck, not blipping.
fn log_feed_failure(feed_key: &str, consecutive: u32, err: &AppError, msg: &str) {
    match failure_log_level(consecutive) {
        FeedLogLevel::Warn => tracing::warn!(
            feed = feed_key,
            consecutive_failures = consecutive,
            error = %err,
            "{msg}"
        ),
        FeedLogLevel::Debug => tracing::debug!(
            feed = feed_key,
            consecutive_failures = consecutive,
            error = %err,
            "{msg}"
        ),
    }
}

/// True when `upstream_url` points at a host the public npm replication feed
/// covers.
pub fn upstream_covered_by_npm_feed(upstream_url: &str) -> bool {
    Url::parse(upstream_url)
        .ok()
        .and_then(|url| {
            url.host_str()
                .map(|host| NPM_PUBLIC_REGISTRY_HOSTS.contains(&host.to_ascii_lowercase().as_str()))
        })
        .unwrap_or(false)
}

/// Wait `period`, returning `true` early when cancellation fires.
async fn cancelled_within(cancel: &CancellationToken, period: Duration) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => true,
        _ = tokio::time::sleep(period) => false,
    }
}

// ---------------------------------------------------------------------------
// npm replication feed adapter
// ---------------------------------------------------------------------------

/// Wire shape of a `_changes` response. Tolerant by construction: unknown
/// fields are ignored and every field is optional, so a feed re-shape degrades
/// to skipped rows or a missing cursor, never a panic.
#[derive(Debug, Deserialize)]
struct ChangesResponse {
    #[serde(default)]
    results: Vec<ChangeRow>,
    #[serde(default)]
    last_seq: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ChangeRow {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    seq: Option<serde_json::Value>,
}

/// Wire shape of the feed root (`GET /`), used only to read the current head
/// sequence for bootstrap. `replicate.npmjs.com` returns
/// `{"db_name":"registry","engine":"npm-replicate","update_seq":<n>,…}`.
#[derive(Debug, Deserialize)]
struct FeedRoot {
    #[serde(default)]
    update_seq: Option<serde_json::Value>,
}

/// Normalise a sequence value: the feed uses numbers, other/newer feeds may
/// use opaque strings. Anything else is treated as "no cursor" rather than
/// guessed at.
fn seq_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// Read and JSON-parse a response body under [`FEED_MAX_BODY_BYTES`]. Frames
/// are accumulated one at a time so an unbounded/hostile body errors out
/// (feeding normal backoff) instead of OOM-ing the consumer. reqwest transport
/// errors are stripped of their URL via `without_url()` so a credentialed
/// `NPM_UPSTREAM_FEED_URL` (`user:pass@host`) can never surface in a log line.
async fn read_json_capped<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    what: &str,
) -> Result<T> {
    let mut stream = response.bytes_stream();
    let mut buf = bytes::BytesMut::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            AppError::Internal(format!("{what} body unreadable: {}", e.without_url()))
        })?;
        if buf.len().saturating_add(chunk.len()) > FEED_MAX_BODY_BYTES {
            return Err(AppError::Internal(format!(
                "{what} body exceeded the {FEED_MAX_BODY_BYTES}-byte limit"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&buf)
        .map_err(|e| AppError::Internal(format!("{what} body unparseable: {e}")))
}

/// Derive the feed root URL (for bootstrap) from a configured `_changes` URL
/// by stripping a single trailing `_changes` path segment and any query. A
/// non-standard base path (`…/couch/registry/_changes`) is preserved
/// (`…/couch/registry/`); a trailing slash on the configured URL is handled.
/// Only a `_changes` tail is stripped, so an unexpected URL is left intact
/// rather than mangled.
fn feed_root_url(feed_url: &Url) -> Result<Url> {
    let mut root = feed_url.clone();
    root.set_query(None);
    root.set_fragment(None);
    {
        let mut segs = root.path_segments_mut().map_err(|()| {
            AppError::Config(format!("npm feed URL '{feed_url}' cannot be a base"))
        })?;
        // Drop the empty segment a trailing slash leaves behind first.
        segs.pop_if_empty();
    }
    let ends_in_changes = root.path_segments().and_then(|mut s| s.next_back()) == Some("_changes");
    if ends_in_changes {
        root.path_segments_mut()
            .map_err(|()| AppError::Config(format!("npm feed URL '{feed_url}' cannot be a base")))?
            .pop()
            .push("");
    }
    Ok(root)
}

/// Adapter for npm's public replication feed. Polls `_changes?since&limit`
/// (the `npm-replicate` engine rejects CouchDB's long-poll controls) and
/// bootstraps the head cursor from the feed root's `update_seq`.
pub struct NpmReplicationFeedAdapter {
    http: reqwest::Client,
    url: Url,
    feed_key: String,
}

impl NpmReplicationFeedAdapter {
    pub fn new(url: &str) -> Result<Self> {
        // Entry-point SSRF check on the configured feed endpoint, the same
        // guard the other outbound-fetch paths (cargo/composer/remote
        // instances) apply before issuing a request. `base_client_builder`'s
        // redirect policy only re-validates *redirect* hops, so without this
        // a feed URL pointing straight at a private/link-local/metadata
        // address (169.254.169.254, internal service names, RFC1918, …)
        // would be fetched directly. Rejecting here means such a URL simply
        // never starts a consumer rather than reaching an internal target.
        crate::api::validation::validate_outbound_url(url, "npm upstream feed URL")?;
        Self::from_url_unchecked(url)
    }

    /// Build the adapter without the entry-point SSRF check. Production code
    /// must use [`Self::new`]; this exists only so unit tests can point the
    /// adapter at a loopback mock server, which [`Self::new`] correctly
    /// refuses. The redirect-hop SSRF policy on the shared client still
    /// applies to every request either constructor's adapter issues.
    fn from_url_unchecked(url: &str) -> Result<Self> {
        let parsed = Url::parse(url)
            .map_err(|e| AppError::Config(format!("invalid npm feed URL '{url}': {e}")))?;
        // The shared builder carries the custom-CA bundle and the SSRF
        // redirect policy every outbound client in the app uses.
        let http = crate::services::http_client::base_client_builder()
            .timeout(NPM_FEED_HTTP_TIMEOUT)
            .user_agent(concat!("artifact-keeper/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| AppError::Config(format!("building npm feed HTTP client: {e}")))?;
        // Strip userinfo so credentials in the configured URL never reach
        // the DB key or log lines that carry `feed = feed_key`.
        let mut display = parsed.clone();
        let _ = display.set_username("");
        let _ = display.set_password(None);
        Ok(Self {
            http,
            feed_key: format!("npm-changes:{display}"),
            url: parsed,
        })
    }
}

#[async_trait]
impl UpstreamFeedAdapter for NpmReplicationFeedAdapter {
    fn feed_key(&self) -> &str {
        &self.feed_key
    }

    fn idle_poll_interval(&self) -> Duration {
        NPM_FEED_IDLE_POLL_INTERVAL
    }

    /// Read the current head sequence from the feed root (`GET /`). The engine
    /// dropped CouchDB's `since=now`, so the head must be discovered over the
    /// network. Any failure — unreachable root, non-2xx, oversized/unparseable
    /// body, or a root without a usable `update_seq` — is an `Err`: the
    /// consumer must back off and retry, never fall through to polling from
    /// genesis (replaying the registry's entire change history).
    async fn bootstrap_cursor(&self) -> Result<Option<String>> {
        let root = feed_root_url(&self.url)?;
        let response = self.http.get(root).send().await.map_err(|e| {
            AppError::Internal(format!(
                "npm feed bootstrap request failed: {}",
                e.without_url()
            ))
        })?;
        if !response.status().is_success() {
            return Err(AppError::Internal(format!(
                "npm feed bootstrap answered {}",
                response.status()
            )));
        }
        let root: FeedRoot = read_json_capped(response, "npm feed bootstrap").await?;
        let seq = root
            .update_seq
            .as_ref()
            .and_then(seq_to_string)
            .ok_or_else(|| {
                AppError::Internal(
                    "npm feed bootstrap: root response had no usable update_seq".to_string(),
                )
            })?;
        Ok(Some(seq))
    }

    async fn poll(&self, since: Option<&str>) -> Result<FeedBatch> {
        let mut url = self.url.clone();
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("limit", &NPM_FEED_BATCH_LIMIT.to_string());
            if let Some(since) = since {
                query.append_pair("since", since);
            }
        }
        let response = self.http.get(url).send().await.map_err(|e| {
            AppError::Internal(format!("npm feed request failed: {}", e.without_url()))
        })?;
        if !response.status().is_success() {
            return Err(AppError::Internal(format!(
                "npm feed answered {}",
                response.status()
            )));
        }
        let changes: ChangesResponse = read_json_capped(response, "npm feed").await?;

        // A poll returning the full row limit signals a backlog is draining.
        // Measured against the raw row count (pre-filter), since the limit
        // applies to change rows, not to the packages we keep.
        let batch_was_full = changes.results.len() as u32 >= NPM_FEED_BATCH_LIMIT;
        // The response-level cursor is authoritative; fall back to the last
        // row's seq when a re-shaped feed omits it.
        let last_seq = changes
            .last_seq
            .as_ref()
            .and_then(seq_to_string)
            .or_else(|| {
                changes
                    .results
                    .iter()
                    .rev()
                    .find_map(|row| row.seq.as_ref().and_then(seq_to_string))
            });
        let events = changes
            .results
            .into_iter()
            .filter_map(|row| row.id)
            // Design documents are feed internals, not packages.
            .filter(|id| !id.is_empty() && !id.starts_with("_design/"))
            .map(|package| FeedEvent { package })
            .collect();
        Ok(FeedBatch {
            events,
            last_seq,
            batch_was_full,
        })
    }
}

// ---------------------------------------------------------------------------
// Default action: computed-packument invalidation
// ---------------------------------------------------------------------------

/// Default [`FeedAction`]: drop the cached computed packuments for the
/// changed package in every remote npm repository whose upstream the feed
/// covers, and in every virtual repository containing one. The next request
/// (or background refresh) recomputes from the upstream, so a fresh publish
/// becomes visible without waiting out the fresh window.
pub struct PackumentInvalidationAction {
    db: PgPool,
    cache: Arc<NpmPackumentCache>,
}

impl PackumentInvalidationAction {
    pub fn new(db: PgPool, cache: Arc<NpmPackumentCache>) -> Self {
        Self { db, cache }
    }
}

#[async_trait]
impl FeedAction for PackumentInvalidationAction {
    async fn apply(&self, events: &[FeedEvent]) -> bool {
        // Resolve the covered repositories (and their virtuals) once per
        // batch; the per-event work is then pure cache invalidation.
        let repos: Vec<(uuid::Uuid, String, Option<String>)> = match sqlx::query_as(
            "SELECT id, key, upstream_url FROM repositories \
             WHERE format = 'npm'::repository_format \
             AND repo_type = 'remote'::repository_type",
        )
        .fetch_all(&self.db)
        .await
        {
            Ok(repos) => repos,
            Err(e) => {
                tracing::warn!(error = %e, "npm feed invalidation skipped: repo lookup failed");
                return false;
            }
        };
        for (repo_id, repo_key, upstream_url) in repos {
            if !upstream_url
                .as_deref()
                .is_some_and(upstream_covered_by_npm_feed)
            {
                continue;
            }
            let virtual_keys = npm_packument_cache::virtual_repo_keys(&self.db, repo_id).await;
            for event in events {
                self.cache
                    .invalidate_package(&repo_key, &event.package)
                    .await;
                for virtual_key in &virtual_keys {
                    self.cache
                        .invalidate_package(virtual_key, &event.package)
                        .await;
                }
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Resume-state store
// ---------------------------------------------------------------------------

/// Postgres-backed [`FeedStateStore`] over `upstream_feed_state`
/// (migration 156).
pub struct PgFeedStateStore {
    pool: PgPool,
}

impl PgFeedStateStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl FeedStateStore for PgFeedStateStore {
    async fn load(&self, feed_key: &str) -> Result<Option<String>> {
        Ok(
            sqlx::query_scalar("SELECT last_seq FROM upstream_feed_state WHERE feed_key = $1")
                .bind(feed_key)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    async fn save(&self, feed_key: &str, last_seq: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO upstream_feed_state (feed_key, last_seq, updated_at) \
             VALUES ($1, $2, now()) \
             ON CONFLICT (feed_key) \
             DO UPDATE SET last_seq = EXCLUDED.last_seq, updated_at = now()",
        )
        .bind(feed_key)
        .bind(last_seq)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Consumer
// ---------------------------------------------------------------------------

/// Runs one feed subscription as a cluster-wide singleton: only the replica
/// holding the advisory lock polls, everyone else re-checks on an interval
/// so leadership fails over when the leader (or its lock connection) dies.
pub struct FeedConsumer {
    adapter: Arc<dyn UpstreamFeedAdapter>,
    action: Arc<dyn FeedAction>,
    state: Arc<dyn FeedStateStore>,
    lock: Arc<dyn ClusterLock>,
    cancel: CancellationToken,
    leader_retry: Duration,
    leader_term: Duration,
    backoff_initial: Duration,
    backoff_max: Duration,
}

impl FeedConsumer {
    pub fn new(
        adapter: Arc<dyn UpstreamFeedAdapter>,
        action: Arc<dyn FeedAction>,
        state: Arc<dyn FeedStateStore>,
        lock: Arc<dyn ClusterLock>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            adapter,
            action,
            state,
            lock,
            cancel,
            leader_retry: LEADER_RETRY_INTERVAL,
            leader_term: LEADER_TERM,
            backoff_initial: FEED_BACKOFF_INITIAL,
            backoff_max: FEED_BACKOFF_MAX,
        }
    }

    /// Test seam: shrink the loop intervals so tests converge in
    /// milliseconds instead of seconds. Idle pacing is adapter-driven
    /// (`idle_poll_interval`), so the scripted adapter shrinks that.
    #[cfg(test)]
    fn with_timings(
        mut self,
        leader_retry: Duration,
        leader_term: Duration,
        backoff_initial: Duration,
        backoff_max: Duration,
    ) -> Self {
        self.leader_retry = leader_retry;
        self.leader_term = leader_term;
        self.backoff_initial = backoff_initial;
        self.backoff_max = backoff_max;
        self
    }

    /// Run until cancelled. Never returns an error: every failure mode is
    /// retried (feed errors) or waited out (leadership held elsewhere) —
    /// best-effort by design.
    pub async fn run(self) {
        let feed_key = self.adapter.feed_key().to_string();
        let lock_object = lease_object_id(&feed_key);
        // Consecutive feed-connectivity failures (poll + bootstrap), tracked
        // across leadership terms so a permanently-broken feed escalates to
        // warn even though each bootstrap failure ends its term.
        let mut failures: u32 = 0;
        loop {
            if self.cancel.is_cancelled() {
                return;
            }
            let lease = match self
                .lock
                .try_acquire(UPSTREAM_FEED_LOCK_CLASS, lock_object)
                .await
            {
                Ok(Some(lease)) => lease,
                // Held elsewhere, or lock infrastructure down. Either way,
                // do NOT consume: N replicas polling one feed is exactly
                // what the lock prevents, and the packument cache's TTL
                // floor covers a no-consumer window.
                Ok(None) => {
                    if cancelled_within(&self.cancel, self.leader_retry).await {
                        return;
                    }
                    continue;
                }
                Err(e) => {
                    tracing::debug!(
                        feed = feed_key,
                        error = %e,
                        "upstream feed leadership check failed; retrying"
                    );
                    if cancelled_within(&self.cancel, self.leader_retry).await {
                        return;
                    }
                    continue;
                }
            };
            tracing::info!(
                feed = feed_key,
                "upstream feed consumer: leadership acquired"
            );
            self.consume_for_one_term(&feed_key, &mut failures).await;
            // Step down at term end (or cancellation) and re-contend, so a
            // lock silently lost to a dead connection converges back to a
            // single consumer within one term instead of persisting until
            // process restart.
            lease.release().await;
            if self.cancel.is_cancelled() {
                return;
            }
        }
    }

    /// One leadership term: poll, apply actions, persist the cursor; back
    /// off on feed errors. Returns at term end or on cancellation. `failures`
    /// is the run-wide consecutive-failure counter driving log escalation.
    async fn consume_for_one_term(&self, feed_key: &str, failures: &mut u32) {
        let mut since = match self.state.load(feed_key).await {
            Ok(Some(seq)) => Some(seq),
            // First enablement: bootstrap the head cursor from the adapter.
            Ok(None) => match self.adapter.bootstrap_cursor().await {
                Ok(cursor) => {
                    Self::note_recovery(feed_key, failures);
                    // Persist the bootstrapped head before the first poll: at
                    // head the first poll echoes the same seq, so the
                    // `advanced`-gated save below never fires and the stored
                    // cursor stays empty until the feed moves. A restart or
                    // failover in that window would re-bootstrap to a newer
                    // head and silently skip the interim events (a crashlooping
                    // consumer would never persist at all). A failed save only
                    // loses the resume position — continue on the in-memory
                    // cursor rather than failing the term.
                    if let Some(seq) = cursor.as_deref() {
                        if let Err(e) = self.state.save(feed_key, seq).await {
                            tracing::warn!(
                                feed = feed_key,
                                error = %e,
                                "upstream feed cursor not persisted; continuing"
                            );
                        }
                    }
                    cursor
                }
                Err(e) => {
                    // Bootstrap failed. Falling through to a bare poll could
                    // replay the upstream's entire history from genesis, so
                    // sit the term out exactly as for an unreadable cursor;
                    // the next leader retries the bootstrap.
                    *failures += 1;
                    log_feed_failure(
                        feed_key,
                        *failures,
                        &e,
                        "upstream feed head bootstrap failed; skipping this term",
                    );
                    cancelled_within(&self.cancel, self.leader_retry).await;
                    return;
                }
            },
            Err(e) => {
                // Falling back to a bootstrap here would silently skip
                // everything between the stored cursor and now, and the next
                // save would overwrite the stored cursor. Sit the term out;
                // the next leader retries the load.
                tracing::warn!(
                    feed = feed_key,
                    error = %e,
                    "upstream feed cursor unreadable; skipping this term"
                );
                // run() re-contends the lock as soon as a term ends, so
                // without a pause a persistently unreadable cursor becomes a
                // hot acquire/release loop.
                cancelled_within(&self.cancel, self.leader_retry).await;
                return;
            }
        };
        let mut backoff = self.backoff_initial;
        let term_ends = tokio::time::sleep(self.leader_term);
        tokio::pin!(term_ends);
        loop {
            let polled = tokio::select! {
                _ = self.cancel.cancelled() => return,
                _ = &mut term_ends => return,
                polled = self.adapter.poll(since.as_deref()) => polled,
            };
            match polled {
                Ok(batch) => {
                    // A successful poll means the feed is reachable and speaking
                    // the expected dialect; clear any failure streak.
                    Self::note_recovery(feed_key, failures);
                    if !batch.events.is_empty() && !self.action.apply(&batch.events).await {
                        // Advancing the cursor past an unapplied batch would
                        // lose those invalidations for good; hold position
                        // and replay the batch after a backoff.
                        tracing::warn!(
                            feed = feed_key,
                            backoff_secs = backoff.as_secs_f32(),
                            "upstream feed actions failed; replaying the batch"
                        );
                        if cancelled_within(&self.cancel, backoff).await {
                            return;
                        }
                        backoff = next_backoff(backoff, self.backoff_max);
                        continue;
                    }
                    let advanced =
                        batch.last_seq.is_some() && batch.last_seq.as_deref() != since.as_deref();
                    if let Some(last_seq) = batch.last_seq {
                        if advanced {
                            // Only persist when the cursor actually moved: idle
                            // rounds echo the same seq, and re-upserting it every
                            // poll is pure DB churn. A failed save only loses the
                            // resume position — consumption continues and a later
                            // leader replays from the last persisted cursor
                            // (idempotent).
                            if let Err(e) = self.state.save(feed_key, &last_seq).await {
                                tracing::warn!(
                                    feed = feed_key,
                                    error = %e,
                                    "upstream feed cursor not persisted; continuing"
                                );
                            }
                        }
                        since = Some(last_seq);
                    }
                    if advanced {
                        backoff = self.backoff_initial;
                    }
                    if !batch.events.is_empty() && !advanced {
                        // Events but no cursor progress: the next poll would
                        // replay the same batch (e.g. a feed re-shape whose
                        // seqs we cannot normalise). Escalating backoff bounds
                        // the replay rate; actions stay idempotent. Checked
                        // before the drain path so a full-but-stalled batch
                        // still backs off rather than hot-looping.
                        tracing::warn!(
                            feed = feed_key,
                            backoff_secs = backoff.as_secs_f32(),
                            "upstream feed returned events without advancing the cursor; \
                             backing off to bound the replay"
                        );
                        if cancelled_within(&self.cancel, backoff).await {
                            return;
                        }
                        backoff = next_backoff(backoff, self.backoff_max);
                    } else if batch.batch_was_full && advanced {
                        // The poll hit the row limit *and* the cursor moved: a
                        // backlog is draining (e.g. after downtime). Re-poll
                        // immediately instead of pacing, but still honour
                        // cancellation promptly. Draining requires progress — a
                        // full batch that did not advance (e.g. all rows
                        // filtered out) falls to the idle-pacing branch below
                        // rather than hot-looping.
                        if self.cancel.is_cancelled() {
                            return;
                        }
                    } else {
                        // Partial or empty batch — steady state. Pace the next
                        // poll to the adapter's idle interval so a feed that
                        // answers instantly cannot hot-loop.
                        if cancelled_within(&self.cancel, self.adapter.idle_poll_interval()).await {
                            return;
                        }
                    }
                }
                Err(e) => {
                    *failures += 1;
                    log_feed_failure(
                        feed_key,
                        *failures,
                        &e,
                        "upstream feed poll failed; backing off",
                    );
                    if cancelled_within(&self.cancel, backoff).await {
                        return;
                    }
                    backoff = next_backoff(backoff, self.backoff_max);
                }
            }
        }
    }

    /// Clear the failure streak, logging recovery at info when a streak ended.
    fn note_recovery(feed_key: &str, failures: &mut u32) {
        if *failures > 0 {
            tracing::info!(
                feed = feed_key,
                failures_before_recovery = *failures,
                "upstream feed recovered"
            );
            *failures = 0;
        }
    }
}

/// Start the npm replication-feed consumer described by the configuration.
/// Returns `None` (with a log, never a startup failure) when disabled or
/// misconfigured.
pub fn spawn_npm_feed_consumer(
    config: &Config,
    db: PgPool,
    cache: Option<Arc<NpmPackumentCache>>,
    cancel: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.npm_upstream_feed_enabled {
        return None;
    }
    let Some(cache) = cache else {
        tracing::warn!(
            "NPM_UPSTREAM_FEED_ENABLED is set but the packument cache is disabled; \
             there is nothing to invalidate, feed consumer not started"
        );
        return None;
    };
    let adapter = match NpmReplicationFeedAdapter::new(&config.npm_upstream_feed_url) {
        Ok(adapter) => Arc::new(adapter),
        Err(e) => {
            tracing::warn!(error = %e, "NPM_UPSTREAM_FEED_URL rejected; feed consumer not started");
            return None;
        }
    };
    let consumer = FeedConsumer::new(
        adapter,
        Arc::new(PackumentInvalidationAction::new(db.clone(), cache)),
        Arc::new(PgFeedStateStore::new(db.clone())),
        Arc::new(PgAdvisoryLock::new(db)),
        cancel,
    );
    Some(tokio::spawn(consumer.run()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    use crate::services::cluster_lock::{ErroringClusterLock, InMemoryClusterLock};

    // -- pure helpers -----------------------------------------------------------

    #[test]
    fn next_backoff_doubles_and_caps() {
        let max = Duration::from_secs(60);
        assert_eq!(
            next_backoff(Duration::from_secs(1), max),
            Duration::from_secs(2)
        );
        assert_eq!(
            next_backoff(Duration::from_secs(40), max),
            Duration::from_secs(60)
        );
        assert_eq!(next_backoff(max, max), max);
    }

    #[test]
    fn seq_normalisation_accepts_numbers_and_strings_only() {
        assert_eq!(
            seq_to_string(&serde_json::json!(42)),
            Some("42".to_string())
        );
        assert_eq!(
            seq_to_string(&serde_json::json!("7788-abc")),
            Some("7788-abc".to_string())
        );
        assert_eq!(seq_to_string(&serde_json::json!("")), None);
        assert_eq!(seq_to_string(&serde_json::json!(null)), None);
        assert_eq!(seq_to_string(&serde_json::json!(["complex", 1])), None);
    }

    #[test]
    fn npm_feed_coverage_is_host_scoped() {
        assert!(upstream_covered_by_npm_feed("https://registry.npmjs.org"));
        assert!(upstream_covered_by_npm_feed(
            "https://registry.npmjs.com/some/path"
        ));
        assert!(upstream_covered_by_npm_feed("https://REGISTRY.NPMJS.ORG"));
        assert!(!upstream_covered_by_npm_feed(
            "https://registry.internal.example.com"
        ));
        assert!(!upstream_covered_by_npm_feed(
            "https://evilregistry.npmjs.org.attacker.example"
        ));
        assert!(!upstream_covered_by_npm_feed("not a url"));
        assert!(!upstream_covered_by_npm_feed(""));
    }

    #[test]
    fn failure_log_level_keeps_first_two_at_debug_then_escalates() {
        // Blips (1-2) stay quiet; the 3rd escalates to warn; the intervening
        // failures drop back to debug; every ~10th re-warns so a permanently
        // broken feed stays visible without flooding.
        assert_eq!(failure_log_level(0), FeedLogLevel::Debug);
        assert_eq!(failure_log_level(1), FeedLogLevel::Debug);
        assert_eq!(failure_log_level(2), FeedLogLevel::Debug);
        assert_eq!(failure_log_level(3), FeedLogLevel::Warn);
        for n in 4..=9 {
            assert_eq!(failure_log_level(n), FeedLogLevel::Debug, "n={n}");
        }
        assert_eq!(failure_log_level(10), FeedLogLevel::Warn);
        for n in 11..=19 {
            assert_eq!(failure_log_level(n), FeedLogLevel::Debug, "n={n}");
        }
        assert_eq!(failure_log_level(20), FeedLogLevel::Warn);
        assert_eq!(failure_log_level(30), FeedLogLevel::Warn);
    }

    #[test]
    fn feed_root_url_strips_trailing_changes_segment() {
        let root = |u: &str| feed_root_url(&Url::parse(u).unwrap()).unwrap().to_string();
        assert_eq!(
            root("https://replicate.npmjs.com/_changes"),
            "https://replicate.npmjs.com/"
        );
        assert_eq!(
            root("https://replicate.npmjs.com/_changes/"),
            "https://replicate.npmjs.com/",
            "a trailing slash must not defeat the strip"
        );
        assert_eq!(
            root("https://replicate.npmjs.com/_changes?since=5&limit=200"),
            "https://replicate.npmjs.com/",
            "the query is dropped for the root request"
        );
        assert_eq!(
            root("https://mirror.example/couch/registry/_changes"),
            "https://mirror.example/couch/registry/",
            "a non-standard base path is preserved"
        );
        assert_eq!(
            root("https://mirror.example/feed"),
            "https://mirror.example/feed",
            "a URL that does not end in _changes is left intact"
        );
    }

    // -- npm adapter (wiremock) -------------------------------------------------

    fn changes_body(rows: serde_json::Value, last_seq: serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "results": rows, "last_seq": last_seq })
    }

    #[tokio::test]
    async fn npm_adapter_polls_with_since_and_limit_only() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/_changes"))
            .and(query_param("since", "41"))
            .and(query_param("limit", NPM_FEED_BATCH_LIMIT.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(changes_body(
                serde_json::json!([
                    {"seq": 42, "id": "lodash", "changes": [{"rev": "1-x"}]},
                    // A deletion row (unpublish) carries a normal id and must
                    // still invalidate the cached packument.
                    {"seq": 1783991, "id": "gone-pkg", "changes": [{"rev": "2-y"}], "deleted": true},
                ]),
                serde_json::json!(1783991),
            )))
            .mount(&server)
            .await;

        let adapter =
            NpmReplicationFeedAdapter::from_url_unchecked(&format!("{}/_changes", server.uri()))
                .expect("adapter");
        let batch = adapter.poll(Some("41")).await.expect("poll");
        assert_eq!(
            batch.events,
            vec![
                FeedEvent {
                    package: "lodash".to_string()
                },
                FeedEvent {
                    package: "gone-pkg".to_string()
                },
            ]
        );
        assert_eq!(batch.last_seq, Some("1783991".to_string()));
        assert!(!batch.batch_was_full, "two rows is far below the limit");

        // The npm-replicate engine 400s on CouchDB's long-poll controls; the
        // adapter must never send them.
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 1);
        let query = requests[0].url.query().unwrap_or("");
        assert!(!query.contains("feed="), "must not send feed=; got {query}");
        assert!(
            !query.contains("timeout="),
            "must not send timeout=; got {query}"
        );
        assert!(
            !query.contains("since=now"),
            "must not send since=now; got {query}"
        );
    }

    #[tokio::test]
    async fn npm_adapter_first_poll_omits_since() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/_changes"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(changes_body(serde_json::json!([]), serde_json::json!(7))),
            )
            .mount(&server)
            .await;

        let adapter =
            NpmReplicationFeedAdapter::from_url_unchecked(&format!("{}/_changes", server.uri()))
                .expect("adapter");
        let batch = adapter.poll(None).await.expect("poll");
        assert!(batch.events.is_empty());
        assert_eq!(batch.last_seq, Some("7".to_string()));

        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 1);
        let query = requests[0].url.query().unwrap_or("");
        assert!(
            !query.contains("since"),
            "a bare poll must send no since cursor; got {query}"
        );
        assert!(
            query.contains("limit"),
            "every poll still bounds the batch with limit; got {query}"
        );
    }

    #[tokio::test]
    async fn npm_adapter_handles_past_head_since_echo() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // A `since` past the head returns no rows and echoes the requested
        // seq back as last_seq (verified live). That is an idle round, not an
        // error, and the cursor does not move.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/_changes"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(changes_body(serde_json::json!([]), serde_json::json!(999))),
            )
            .mount(&server)
            .await;

        let adapter =
            NpmReplicationFeedAdapter::from_url_unchecked(&format!("{}/_changes", server.uri()))
                .expect("adapter");
        let batch = adapter.poll(Some("999")).await.expect("poll");
        assert!(batch.events.is_empty());
        assert_eq!(batch.last_seq, Some("999".to_string()));
        assert!(!batch.batch_was_full);
    }

    #[tokio::test]
    async fn npm_adapter_flags_a_full_batch() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let rows: Vec<serde_json::Value> = (0..NPM_FEED_BATCH_LIMIT)
            .map(|i| serde_json::json!({"seq": i + 1, "id": format!("pkg-{i}")}))
            .collect();
        Mock::given(method("GET"))
            .and(path("/_changes"))
            .respond_with(ResponseTemplate::new(200).set_body_json(changes_body(
                serde_json::json!(rows),
                serde_json::json!(NPM_FEED_BATCH_LIMIT),
            )))
            .mount(&server)
            .await;

        let adapter =
            NpmReplicationFeedAdapter::from_url_unchecked(&format!("{}/_changes", server.uri()))
                .expect("adapter");
        let batch = adapter.poll(Some("0")).await.expect("poll");
        assert_eq!(batch.events.len(), NPM_FEED_BATCH_LIMIT as usize);
        assert!(
            batch.batch_was_full,
            "a poll returning the row limit must flag a draining backlog"
        );
    }

    #[tokio::test]
    async fn npm_adapter_tolerates_malformed_rows_and_feed_reshapes() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // String seqs, rows without ids, design docs, unknown fields, and a
        // missing response-level last_seq (falls back to the last row seq).
        Mock::given(method("GET"))
            .and(path("/_changes"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [
                    {"seq": "10-abc", "id": "left-pad", "novel_field": true},
                    {"seq": "11-def"},
                    {"seq": "12-ghi", "id": "_design/app"},
                    {"seq": "13-jkl", "id": ""},
                    {"id": "no-seq-pkg"},
                ],
                "unexpected": {"shape": []}
            })))
            .mount(&server)
            .await;

        let adapter =
            NpmReplicationFeedAdapter::from_url_unchecked(&format!("{}/_changes", server.uri()))
                .expect("adapter");
        let batch = adapter.poll(None).await.expect("poll");
        assert_eq!(
            batch.events,
            vec![
                FeedEvent {
                    package: "left-pad".to_string()
                },
                FeedEvent {
                    package: "no-seq-pkg".to_string()
                },
            ],
            "malformed rows are skipped, well-formed ones kept"
        );
        assert_eq!(
            batch.last_seq,
            Some("13-jkl".to_string()),
            "with no response-level cursor, the last row seq is the fallback"
        );
        assert!(!batch.batch_was_full);
    }

    #[tokio::test]
    async fn npm_adapter_surfaces_http_and_parse_failures() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/unavailable/_changes"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/garbage/_changes"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>not couch</html>"))
            .mount(&server)
            .await;

        let unavailable = NpmReplicationFeedAdapter::from_url_unchecked(&format!(
            "{}/unavailable/_changes",
            server.uri()
        ))
        .expect("adapter");
        assert!(
            unavailable.poll(None).await.is_err(),
            "5xx must be an error"
        );

        let garbage = NpmReplicationFeedAdapter::from_url_unchecked(&format!(
            "{}/garbage/_changes",
            server.uri()
        ))
        .expect("adapter");
        assert!(
            garbage.poll(None).await.is_err(),
            "an unparseable body must be an error"
        );
    }

    #[tokio::test]
    async fn npm_adapter_bootstraps_head_from_root_update_seq() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // The real root shape, update_seq as a number.
        let numeric = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "db_name": "registry",
                "engine": "npm-replicate",
                "doc_count": 4_205_429u64,
                "update_seq": 119_510_110u64,
            })))
            .mount(&numeric)
            .await;
        let adapter =
            NpmReplicationFeedAdapter::from_url_unchecked(&format!("{}/_changes", numeric.uri()))
                .expect("adapter");
        assert_eq!(
            adapter.bootstrap_cursor().await.expect("bootstrap"),
            Some("119510110".to_string()),
            "the head cursor must come from the root update_seq, never genesis"
        );

        // Some feeds carry an opaque string update_seq; tolerate it too.
        let stringy = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "update_seq": "500-opaque",
            })))
            .mount(&stringy)
            .await;
        let adapter =
            NpmReplicationFeedAdapter::from_url_unchecked(&format!("{}/_changes", stringy.uri()))
                .expect("adapter");
        assert_eq!(
            adapter.bootstrap_cursor().await.expect("bootstrap"),
            Some("500-opaque".to_string())
        );
    }

    #[tokio::test]
    async fn npm_adapter_bootstrap_failure_is_an_error_never_genesis() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Root reachable but carrying no usable update_seq: must be an Err so
        // the consumer backs off rather than polling from seq 0.
        let no_seq = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"db_name": "registry"})),
            )
            .mount(&no_seq)
            .await;
        let adapter =
            NpmReplicationFeedAdapter::from_url_unchecked(&format!("{}/_changes", no_seq.uri()))
                .expect("adapter");
        assert!(
            adapter.bootstrap_cursor().await.is_err(),
            "a root without update_seq must fail bootstrap, not start from genesis"
        );

        // Root 5xx: also an Err.
        let down = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&down)
            .await;
        let adapter =
            NpmReplicationFeedAdapter::from_url_unchecked(&format!("{}/_changes", down.uri()))
                .expect("adapter");
        assert!(
            adapter.bootstrap_cursor().await.is_err(),
            "a 5xx root must fail bootstrap"
        );
    }

    #[tokio::test]
    async fn npm_adapter_rejects_oversized_bodies() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // A body past FEED_MAX_BODY_BYTES must error (feeding backoff), never
        // buffer without bound.
        let server = MockServer::start().await;
        let oversized = vec![b' '; FEED_MAX_BODY_BYTES + 1];
        Mock::given(method("GET"))
            .and(path("/_changes"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(oversized))
            .mount(&server)
            .await;

        let adapter =
            NpmReplicationFeedAdapter::from_url_unchecked(&format!("{}/_changes", server.uri()))
                .expect("adapter");
        assert!(
            adapter.poll(Some("1")).await.is_err(),
            "an over-cap body must be rejected, not buffered unbounded"
        );
    }

    #[tokio::test]
    async fn npm_adapter_errors_never_leak_credentials() {
        // reqwest's Error Display includes the request URL verbatim, userinfo
        // and all. An operator can configure a credentialed feed URL, so both
        // the poll and bootstrap error paths must scrub it via without_url().
        // Port 1 is never listening → an immediate transport error.
        let adapter = NpmReplicationFeedAdapter::from_url_unchecked(
            "http://feeduser:sup3rsecret@127.0.0.1:1/_changes",
        )
        .expect("adapter");

        let poll_msg = adapter
            .poll(Some("1"))
            .await
            .expect_err("poll must fail against a dead port")
            .to_string();
        assert!(
            !poll_msg.contains("sup3rsecret"),
            "password leaked in poll error: {poll_msg}"
        );
        assert!(
            !poll_msg.contains("feeduser"),
            "username leaked in poll error: {poll_msg}"
        );

        let boot_msg = adapter
            .bootstrap_cursor()
            .await
            .expect_err("bootstrap must fail against a dead port")
            .to_string();
        assert!(
            !boot_msg.contains("sup3rsecret"),
            "password leaked in bootstrap error: {boot_msg}"
        );
        assert!(
            !boot_msg.contains("feeduser"),
            "username leaked in bootstrap error: {boot_msg}"
        );
    }

    #[test]
    fn npm_adapter_rejects_invalid_urls() {
        assert!(NpmReplicationFeedAdapter::new("not a url").is_err());
    }

    #[test]
    fn npm_adapter_rejects_ssrf_feed_urls() {
        // A feed URL aimed straight at an internal/link-local/metadata
        // target must be refused at construction (entry-point SSRF guard),
        // so a misconfigured or hostile NPM_UPSTREAM_FEED_URL can never make
        // the consumer fetch an internal address. Redirect-hop validation
        // alone does not cover the initial request.
        for url in [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1/_changes",
            "http://localhost/_changes",
            "http://[::1]/_changes",
            "http://backend:8080/_changes",
            "http://[::ffff:127.0.0.1]/_changes",
        ] {
            assert!(
                NpmReplicationFeedAdapter::new(url).is_err(),
                "SSRF-blocked feed URL must be rejected: {url}"
            );
        }
        // A normal public feed endpoint still constructs.
        assert!(NpmReplicationFeedAdapter::new(NPM_REPLICATION_FEED_DEFAULT_URL).is_ok());
    }

    #[tokio::test]
    #[ignore = "hits the live npm replication feed"]
    async fn npm_adapter_live_bootstrap_and_poll_smoke() {
        // Proves the fix against reality: bootstrap the head from the real
        // root, then poll once from that head. Run manually:
        //   cargo test --lib npm_adapter_live_bootstrap_and_poll_smoke -- --ignored --nocapture
        let adapter =
            NpmReplicationFeedAdapter::new(NPM_REPLICATION_FEED_DEFAULT_URL).expect("adapter");
        let cursor = adapter
            .bootstrap_cursor()
            .await
            .expect("live bootstrap must succeed")
            .expect("live feed must yield a head cursor");
        assert!(
            cursor.parse::<u64>().is_ok(),
            "npm-replicate head cursor is numeric; got {cursor}"
        );
        let batch = adapter
            .poll(Some(&cursor))
            .await
            .expect("live poll must succeed");
        assert!(
            batch.last_seq.is_some(),
            "a live poll must carry a resume cursor"
        );
        println!(
            "live npm-replicate: head={cursor} events={} last_seq={:?} full={}",
            batch.events.len(),
            batch.last_seq,
            batch.batch_was_full
        );
    }

    // -- consumer ---------------------------------------------------------------

    struct ScriptedAdapter {
        feed_key: String,
        bootstrap_cursor: Option<String>,
        bootstrap_fails: AtomicBool,
        idle: Duration,
        polls: Mutex<VecDeque<Result<FeedBatch>>>,
        sinces: Mutex<Vec<Option<String>>>,
    }

    impl ScriptedAdapter {
        fn build(
            polls: Vec<Result<FeedBatch>>,
            bootstrap_cursor: Option<String>,
            bootstrap_fails: bool,
            idle: Duration,
        ) -> Arc<Self> {
            Arc::new(Self {
                feed_key: "test-feed".to_string(),
                bootstrap_cursor,
                bootstrap_fails: AtomicBool::new(bootstrap_fails),
                idle,
                polls: Mutex::new(polls.into()),
                sinces: Mutex::new(Vec::new()),
            })
        }

        fn new(polls: Vec<Result<FeedBatch>>) -> Arc<Self> {
            Self::build(polls, None, false, Duration::from_millis(10))
        }

        fn with_bootstrap_cursor(polls: Vec<Result<FeedBatch>>, cursor: &str) -> Arc<Self> {
            Self::build(
                polls,
                Some(cursor.to_string()),
                false,
                Duration::from_millis(10),
            )
        }

        fn with_bootstrap_failure(polls: Vec<Result<FeedBatch>>) -> Arc<Self> {
            Self::build(polls, None, true, Duration::from_millis(10))
        }

        fn with_idle(polls: Vec<Result<FeedBatch>>, idle: Duration) -> Arc<Self> {
            Self::build(polls, None, false, idle)
        }

        fn sinces(&self) -> Vec<Option<String>> {
            self.sinces.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl UpstreamFeedAdapter for ScriptedAdapter {
        fn feed_key(&self) -> &str {
            &self.feed_key
        }
        fn idle_poll_interval(&self) -> Duration {
            self.idle
        }
        async fn bootstrap_cursor(&self) -> Result<Option<String>> {
            if self.bootstrap_fails.load(Ordering::SeqCst) {
                Err(AppError::Internal("scripted bootstrap failure".to_string()))
            } else {
                Ok(self.bootstrap_cursor.clone())
            }
        }
        async fn poll(&self, since: Option<&str>) -> Result<FeedBatch> {
            self.sinces
                .lock()
                .unwrap()
                .push(since.map(|s| s.to_string()));
            // Once the script is exhausted, behave like an idle feed that
            // returns empty batches (the consumer paces these).
            self.polls
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Ok(FeedBatch::default()))
        }
    }

    #[derive(Default)]
    struct RecordingAction {
        applied: Mutex<Vec<String>>,
        /// Number of upcoming `apply` calls to fail (recording nothing).
        fail_next: AtomicUsize,
    }

    impl RecordingAction {
        fn applied(&self) -> Vec<String> {
            self.applied.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl FeedAction for RecordingAction {
        async fn apply(&self, events: &[FeedEvent]) -> bool {
            if self
                .fail_next
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                return false;
            }
            let mut applied = self.applied.lock().unwrap();
            applied.extend(events.iter().map(|event| event.package.clone()));
            true
        }
    }

    #[derive(Default)]
    struct MemoryStateStore {
        map: Mutex<HashMap<String, String>>,
        fail_saves: AtomicBool,
        fail_loads: AtomicBool,
    }

    impl MemoryStateStore {
        fn get(&self, feed_key: &str) -> Option<String> {
            self.map.lock().unwrap().get(feed_key).cloned()
        }
        fn put(&self, feed_key: &str, seq: &str) {
            self.map
                .lock()
                .unwrap()
                .insert(feed_key.to_string(), seq.to_string());
        }
    }

    #[async_trait]
    impl FeedStateStore for MemoryStateStore {
        async fn load(&self, feed_key: &str) -> Result<Option<String>> {
            if self.fail_loads.load(Ordering::SeqCst) {
                return Err(AppError::Database("simulated load failure".to_string()));
            }
            Ok(self.get(feed_key))
        }
        async fn save(&self, feed_key: &str, last_seq: &str) -> Result<()> {
            if self.fail_saves.load(Ordering::SeqCst) {
                return Err(AppError::Database("simulated save failure".to_string()));
            }
            self.put(feed_key, last_seq);
            Ok(())
        }
    }

    fn batch(packages: &[&str], last_seq: &str) -> Result<FeedBatch> {
        Ok(FeedBatch {
            events: packages
                .iter()
                .map(|p| FeedEvent {
                    package: p.to_string(),
                })
                .collect(),
            last_seq: Some(last_seq.to_string()),
            batch_was_full: false,
        })
    }

    fn full_batch(packages: &[&str], last_seq: &str) -> Result<FeedBatch> {
        Ok(FeedBatch {
            batch_was_full: true,
            ..batch(packages, last_seq).unwrap()
        })
    }

    fn test_consumer(
        adapter: Arc<ScriptedAdapter>,
        action: Arc<RecordingAction>,
        state: Arc<MemoryStateStore>,
        lock: Arc<dyn ClusterLock>,
        cancel: CancellationToken,
    ) -> FeedConsumer {
        FeedConsumer::new(adapter, action, state, lock, cancel).with_timings(
            Duration::from_millis(20),
            Duration::from_secs(60),
            Duration::from_millis(10),
            Duration::from_millis(40),
        )
    }

    /// Poll `cond` for up to ~5 s; true as soon as it holds.
    async fn wait_until(cond: impl Fn() -> bool) -> bool {
        for _ in 0..500 {
            if cond() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        cond()
    }

    #[tokio::test]
    async fn consumer_applies_events_in_order_and_persists_cursor() {
        let adapter = ScriptedAdapter::new(vec![
            batch(&["lodash", "react"], "2"),
            batch(&["left-pad"], "3"),
        ]);
        let action = Arc::new(RecordingAction::default());
        let state = Arc::new(MemoryStateStore::default());
        let cancel = CancellationToken::new();
        let consumer = test_consumer(
            adapter.clone(),
            action.clone(),
            state.clone(),
            Arc::new(InMemoryClusterLock::default()),
            cancel.clone(),
        );
        let handle = tokio::spawn(consumer.run());

        assert!(
            wait_until(|| action.applied().len() == 3).await,
            "all events must be applied; got {:?}",
            action.applied()
        );
        assert_eq!(action.applied(), vec!["lodash", "react", "left-pad"]);
        assert!(
            wait_until(|| state.get("test-feed") == Some("3".to_string())).await,
            "the cursor must be persisted after each batch"
        );
        // No persisted cursor and a default (Ok(None)) bootstrap → first poll
        // sends no since; the second resumes from the first batch's cursor.
        assert_eq!(adapter.sinces()[0], None);
        assert_eq!(adapter.sinces()[1], Some("2".to_string()));

        cancel.cancel();
        handle.await.expect("consumer task joins after cancel");
    }

    #[tokio::test]
    async fn consumer_resumes_from_persisted_cursor() {
        let adapter = ScriptedAdapter::new(vec![]);
        let action = Arc::new(RecordingAction::default());
        let state = Arc::new(MemoryStateStore::default());
        state.put("test-feed", "42");
        let cancel = CancellationToken::new();
        let consumer = test_consumer(
            adapter.clone(),
            action,
            state,
            Arc::new(InMemoryClusterLock::default()),
            cancel.clone(),
        );
        let handle = tokio::spawn(consumer.run());

        assert!(
            wait_until(|| !adapter.sinces().is_empty()).await,
            "the consumer must start polling"
        );
        assert_eq!(
            adapter.sinces()[0],
            Some("42".to_string()),
            "the first poll must resume from the persisted cursor (no bootstrap)"
        );
        cancel.cancel();
        handle.await.expect("join");
    }

    #[tokio::test]
    async fn consumer_backs_off_on_poll_errors_and_recovers() {
        let adapter = ScriptedAdapter::new(vec![
            Err(AppError::Internal("feed down".to_string())),
            Err(AppError::Internal("feed still down".to_string())),
            batch(&["recovered-pkg"], "9"),
        ]);
        let action = Arc::new(RecordingAction::default());
        let state = Arc::new(MemoryStateStore::default());
        let cancel = CancellationToken::new();
        let consumer = test_consumer(
            adapter.clone(),
            action.clone(),
            state.clone(),
            Arc::new(InMemoryClusterLock::default()),
            cancel.clone(),
        );
        let handle = tokio::spawn(consumer.run());

        assert!(
            wait_until(|| action.applied() == vec!["recovered-pkg"]).await,
            "the consumer must survive feed errors and keep consuming; got {:?}",
            action.applied()
        );
        assert!(
            wait_until(|| state.get("test-feed") == Some("9".to_string())).await,
            "the cursor must advance after recovery"
        );
        cancel.cancel();
        handle.await.expect("join");
    }

    #[tokio::test]
    async fn consumer_keeps_consuming_when_cursor_save_fails() {
        let adapter = ScriptedAdapter::new(vec![batch(&["pkg-a"], "1"), batch(&["pkg-b"], "2")]);
        let action = Arc::new(RecordingAction::default());
        let state = Arc::new(MemoryStateStore::default());
        state.fail_saves.store(true, Ordering::SeqCst);
        let cancel = CancellationToken::new();
        let consumer = test_consumer(
            adapter.clone(),
            action.clone(),
            state.clone(),
            Arc::new(InMemoryClusterLock::default()),
            cancel.clone(),
        );
        let handle = tokio::spawn(consumer.run());

        assert!(
            wait_until(|| action.applied() == vec!["pkg-a", "pkg-b"]).await,
            "a failing cursor store must not stop consumption (best-effort); got {:?}",
            action.applied()
        );
        assert_eq!(
            adapter.sinces().get(1),
            Some(&Some("1".to_string())),
            "the in-memory cursor still advances between polls"
        );
        assert_eq!(state.get("test-feed"), None, "nothing was persisted");
        cancel.cancel();
        handle.await.expect("join");
    }

    #[tokio::test]
    async fn consumer_does_not_poll_while_another_replica_leads() {
        let lock = InMemoryClusterLock::default();
        let feed_key = "test-feed";
        let _leader_lease = lock
            .try_acquire(UPSTREAM_FEED_LOCK_CLASS, lease_object_id(feed_key))
            .await
            .expect("lock")
            .expect("lease");

        let adapter = ScriptedAdapter::new(vec![batch(&["never-applied"], "1")]);
        let action = Arc::new(RecordingAction::default());
        let cancel = CancellationToken::new();
        let consumer = test_consumer(
            adapter.clone(),
            action.clone(),
            Arc::new(MemoryStateStore::default()),
            Arc::new(lock.clone()),
            cancel.clone(),
        );
        let handle = tokio::spawn(consumer.run());

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            adapter.sinces().is_empty(),
            "a non-leader must not open the feed"
        );
        assert!(action.applied().is_empty());
        cancel.cancel();
        handle.await.expect("join");
    }

    #[tokio::test]
    async fn consumer_takes_over_when_the_leader_releases() {
        let lock = InMemoryClusterLock::default();
        let feed_key = "test-feed";
        let leader_lease = lock
            .try_acquire(UPSTREAM_FEED_LOCK_CLASS, lease_object_id(feed_key))
            .await
            .expect("lock")
            .expect("lease");

        let adapter = ScriptedAdapter::new(vec![batch(&["after-failover"], "5")]);
        let action = Arc::new(RecordingAction::default());
        let cancel = CancellationToken::new();
        let consumer = test_consumer(
            adapter.clone(),
            action.clone(),
            Arc::new(MemoryStateStore::default()),
            Arc::new(lock.clone()),
            cancel.clone(),
        );
        let handle = tokio::spawn(consumer.run());

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(adapter.sinces().is_empty(), "still following at this point");

        leader_lease.release().await;
        assert!(
            wait_until(|| action.applied() == vec!["after-failover"]).await,
            "the follower must take over after the leader releases; got {:?}",
            action.applied()
        );
        cancel.cancel();
        handle.await.expect("join");
    }

    #[tokio::test]
    async fn consumer_does_not_poll_when_lock_infrastructure_errors() {
        let adapter = ScriptedAdapter::new(vec![batch(&["never-applied"], "1")]);
        let action = Arc::new(RecordingAction::default());
        let cancel = CancellationToken::new();
        let consumer = test_consumer(
            adapter.clone(),
            action.clone(),
            Arc::new(MemoryStateStore::default()),
            Arc::new(ErroringClusterLock),
            cancel.clone(),
        );
        let handle = tokio::spawn(consumer.run());

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            adapter.sinces().is_empty(),
            "with the lock backend down, no replica may self-elect (that would \
             thundering-herd the feed once the backend recovers)"
        );
        cancel.cancel();
        handle.await.expect("join");
    }

    #[tokio::test]
    async fn consumer_first_run_bootstraps_the_head_cursor() {
        let adapter =
            ScriptedAdapter::with_bootstrap_cursor(vec![batch(&["pkg"], "8")], "119510110");
        let action = Arc::new(RecordingAction::default());
        let state = Arc::new(MemoryStateStore::default());
        let cancel = CancellationToken::new();
        let consumer = test_consumer(
            adapter.clone(),
            action,
            state.clone(),
            Arc::new(InMemoryClusterLock::default()),
            cancel.clone(),
        );
        let handle = tokio::spawn(consumer.run());

        assert!(
            wait_until(|| !adapter.sinces().is_empty()).await,
            "the consumer must start polling"
        );
        assert_eq!(
            adapter.sinces()[0].as_deref(),
            Some("119510110"),
            "with no persisted cursor the first poll must use the bootstrapped head"
        );
        assert!(
            wait_until(|| state.get("test-feed") == Some("8".to_string())).await,
            "the first real cursor replaces the bootstrapped head"
        );
        cancel.cancel();
        handle.await.expect("join");
    }

    #[tokio::test]
    async fn consumer_skips_the_term_when_bootstrap_fails() {
        // Mirrors the cursor-load-failure case: a failing head bootstrap must
        // sit the term out — never poll from genesis — and recover later.
        let adapter =
            ScriptedAdapter::with_bootstrap_failure(vec![batch(&["pkg-after-recovery"], "50")]);
        let action = Arc::new(RecordingAction::default());
        let state = Arc::new(MemoryStateStore::default());
        let cancel = CancellationToken::new();
        let consumer = test_consumer(
            adapter.clone(),
            action.clone(),
            state.clone(),
            Arc::new(InMemoryClusterLock::default()),
            cancel.clone(),
        );
        let handle = tokio::spawn(consumer.run());

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            adapter.sinces().is_empty(),
            "a failed bootstrap must skip the term, not poll from genesis; got {:?}",
            adapter.sinces()
        );
        assert_eq!(state.get("test-feed"), None, "nothing was persisted");

        // A later term retries the bootstrap and resumes once it succeeds.
        adapter.bootstrap_fails.store(false, Ordering::SeqCst);
        assert!(
            wait_until(|| action.applied() == vec!["pkg-after-recovery"]).await,
            "consumption resumes once bootstrap recovers; got {:?}",
            action.applied()
        );
        cancel.cancel();
        handle.await.expect("join");
    }

    #[tokio::test]
    async fn consumer_backs_off_when_events_arrive_without_cursor_progress() {
        // A feed re-shape whose seqs cannot be normalised: events keep
        // coming but the cursor never advances. The consumer must not
        // hot-loop replaying the same batch.
        let stuck = FeedBatch {
            events: vec![FeedEvent {
                package: "stuck-pkg".to_string(),
            }],
            last_seq: None,
            batch_was_full: false,
        };
        let adapter = ScriptedAdapter::new(vec![
            Ok(stuck.clone()),
            Ok(stuck.clone()),
            Ok(stuck.clone()),
            Ok(stuck.clone()),
            Ok(stuck.clone()),
            Ok(stuck.clone()),
            Ok(stuck.clone()),
            Ok(stuck.clone()),
            Ok(stuck.clone()),
            Ok(stuck),
        ]);
        let action = Arc::new(RecordingAction::default());
        let cancel = CancellationToken::new();
        let consumer = test_consumer(
            adapter.clone(),
            action.clone(),
            Arc::new(MemoryStateStore::default()),
            Arc::new(InMemoryClusterLock::default()),
            cancel.clone(),
        );
        let handle = tokio::spawn(consumer.run());

        assert!(
            wait_until(|| !action.applied().is_empty()).await,
            "the stalled batch is still applied at least once"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        let polls = adapter.sinces().len();
        assert!(
            polls <= 12,
            "a stalled cursor must back off, not hot-loop; observed {polls} \
             polls in 300ms with a 10ms initial backoff"
        );
        cancel.cancel();
        handle.await.expect("join");
    }

    #[tokio::test]
    async fn consumer_holds_the_cursor_and_replays_the_batch_when_actions_fail() {
        // The adapter serves the same batch twice: after a failed apply the
        // consumer must re-poll with an unchanged cursor, so the feed
        // replays the events instead of losing them.
        let adapter =
            ScriptedAdapter::new(vec![batch(&["flaky-pkg"], "5"), batch(&["flaky-pkg"], "5")]);
        let action = Arc::new(RecordingAction::default());
        action.fail_next.store(1, Ordering::SeqCst);
        let state = Arc::new(MemoryStateStore::default());
        state.put("test-feed", "4");
        let cancel = CancellationToken::new();
        let consumer = test_consumer(
            adapter.clone(),
            action.clone(),
            state.clone(),
            Arc::new(InMemoryClusterLock::default()),
            cancel.clone(),
        );
        let handle = tokio::spawn(consumer.run());

        assert!(
            wait_until(|| action.applied() == vec!["flaky-pkg"]).await,
            "the batch must be replayed and applied after the failed attempt; got {:?}",
            action.applied()
        );
        assert_eq!(
            adapter.sinces()[..2],
            [Some("4".to_string()), Some("4".to_string())],
            "a failed apply must not advance the poll cursor"
        );
        assert!(
            wait_until(|| state.get("test-feed") == Some("5".to_string())).await,
            "the cursor is persisted once the batch finally applies"
        );
        cancel.cancel();
        handle.await.expect("join");
    }

    #[tokio::test]
    async fn consumer_paces_empty_batches_even_when_the_cursor_advances() {
        // A filtered feed can answer instantly with zero events and a moving
        // seq on every round; that must be paced like any idle round, not
        // hot-looped just because the cursor advanced.
        let polls: Vec<Result<FeedBatch>> = (1..=50)
            .map(|seq| {
                Ok(FeedBatch {
                    events: Vec::new(),
                    last_seq: Some(seq.to_string()),
                    batch_was_full: false,
                })
            })
            .collect();
        let adapter = ScriptedAdapter::new(polls);
        let action = Arc::new(RecordingAction::default());
        let state = Arc::new(MemoryStateStore::default());
        let cancel = CancellationToken::new();
        let consumer = test_consumer(
            adapter.clone(),
            action.clone(),
            state.clone(),
            Arc::new(InMemoryClusterLock::default()),
            cancel.clone(),
        );
        let handle = tokio::spawn(consumer.run());

        assert!(
            wait_until(|| state.get("test-feed").is_some()).await,
            "the advancing cursor must still be persisted between idle rounds"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        let polls = adapter.sinces().len();
        assert!(
            polls <= 40,
            "empty advancing batches must be paced, not hot-looped; observed \
             {polls} polls in 300ms with 10ms pacing"
        );
        cancel.cancel();
        handle.await.expect("join");
    }

    #[tokio::test]
    async fn consumer_drains_full_batches_immediately_but_paces_partial_ones() {
        // A long idle interval: only immediate draining can consume the full
        // batches inside the test window. The partial batch that ends the
        // backlog must then fall back to pacing, so polling stops.
        let polls = vec![
            full_batch(&["a"], "1"),
            full_batch(&["b"], "2"),
            full_batch(&["c"], "3"),
            batch(&["d"], "4"),
        ];
        let adapter = ScriptedAdapter::with_idle(polls, Duration::from_secs(30));
        let action = Arc::new(RecordingAction::default());
        let state = Arc::new(MemoryStateStore::default());
        let cancel = CancellationToken::new();
        let consumer = test_consumer(
            adapter.clone(),
            action.clone(),
            state.clone(),
            Arc::new(InMemoryClusterLock::default()),
            cancel.clone(),
        );
        let handle = tokio::spawn(consumer.run());

        assert!(
            wait_until(|| action.applied() == vec!["a", "b", "c", "d"]).await,
            "full batches must drain immediately despite the long idle interval; got {:?}",
            action.applied()
        );
        // The partial batch "d" advanced the cursor and then paces at the 30s
        // idle, so no further poll happens in a short window.
        let polls_at_pace = adapter.sinces().len();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            adapter.sinces().len(),
            polls_at_pace,
            "a partial batch must pace at the idle interval, not keep draining"
        );
        cancel.cancel();
        handle.await.expect("join");
    }

    #[tokio::test]
    async fn consumer_persists_the_bootstrapped_head_before_the_feed_advances() {
        // At head the first poll echoes the bootstrapped seq (no events, cursor
        // unmoved), so the advance-gated save never fires. The bootstrapped head
        // must be persisted up front regardless, or a restart/failover in that
        // window would re-bootstrap to a newer head and skip the interim events.
        let echo = || {
            Ok(FeedBatch {
                events: Vec::new(),
                last_seq: Some("100".to_string()),
                batch_was_full: false,
            })
        };
        let adapter = ScriptedAdapter::with_bootstrap_cursor(vec![echo(), echo(), echo()], "100");
        let action = Arc::new(RecordingAction::default());
        let state = Arc::new(MemoryStateStore::default());
        let cancel = CancellationToken::new();
        let consumer = test_consumer(
            adapter.clone(),
            action.clone(),
            state.clone(),
            Arc::new(InMemoryClusterLock::default()),
            cancel.clone(),
        );
        let handle = tokio::spawn(consumer.run());

        assert!(
            wait_until(|| state.get("test-feed") == Some("100".to_string())).await,
            "the bootstrapped head must be persisted before the feed advances; got {:?}",
            state.get("test-feed")
        );
        // The feed only ever echoed the head, so nothing overwrote the cursor.
        assert_eq!(
            state.get("test-feed"),
            Some("100".to_string()),
            "an echoing (non-advancing) feed must leave the bootstrapped cursor persisted"
        );
        assert!(
            action.applied().is_empty(),
            "no events means nothing applied"
        );
        cancel.cancel();
        handle.await.expect("join");
    }

    #[tokio::test]
    async fn consumer_does_not_hot_loop_on_full_but_stalled_batches() {
        // A full batch whose rows were all filtered out (no events) and whose
        // cursor did not advance must not be drained: without gating the drain
        // on progress it would re-poll with no sleep — a tight hot-loop. It must
        // fall to idle pacing instead. A long idle interval makes the two
        // outcomes distinguishable inside the test window.
        let stalled = || {
            Ok(FeedBatch {
                events: Vec::new(),
                last_seq: None,
                batch_was_full: true,
            })
        };
        let polls: Vec<Result<FeedBatch>> = std::iter::repeat_with(stalled).take(50).collect();
        let adapter = ScriptedAdapter::with_idle(polls, Duration::from_secs(30));
        let action = Arc::new(RecordingAction::default());
        let state = Arc::new(MemoryStateStore::default());
        let cancel = CancellationToken::new();
        let consumer = test_consumer(
            adapter.clone(),
            action.clone(),
            state.clone(),
            Arc::new(InMemoryClusterLock::default()),
            cancel.clone(),
        );
        let handle = tokio::spawn(consumer.run());

        assert!(
            wait_until(|| !adapter.sinces().is_empty()).await,
            "the consumer must poll at least once"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        let polls = adapter.sinces().len();
        assert!(
            polls <= 2,
            "a full-but-stalled batch must pace at the idle interval, not \
             hot-loop; observed {polls} polls in 300ms with a 30s idle interval"
        );
        assert!(
            action.applied().is_empty(),
            "no events means nothing applied"
        );
        cancel.cancel();
        handle.await.expect("join");
    }

    #[tokio::test]
    async fn consumer_skips_the_term_when_the_cursor_load_fails() {
        let adapter = ScriptedAdapter::new(vec![batch(&["pkg-after-recovery"], "50")]);
        let action = Arc::new(RecordingAction::default());
        let state = Arc::new(MemoryStateStore::default());
        state.put("test-feed", "42");
        state.fail_loads.store(true, Ordering::SeqCst);
        let cancel = CancellationToken::new();
        let consumer = test_consumer(
            adapter.clone(),
            action.clone(),
            state.clone(),
            Arc::new(InMemoryClusterLock::default()),
            cancel.clone(),
        );
        let handle = tokio::spawn(consumer.run());

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            adapter.sinces().is_empty(),
            "an unreadable cursor must skip the term, not resume from a \
             bootstrapped head; got {:?}",
            adapter.sinces()
        );
        assert_eq!(
            state.get("test-feed"),
            Some("42".to_string()),
            "the stored cursor must survive the failed load"
        );

        // A later term retries the load and resumes from the stored cursor.
        state.fail_loads.store(false, Ordering::SeqCst);
        assert!(
            wait_until(|| adapter.sinces().first() == Some(&Some("42".to_string()))).await,
            "recovery must resume from the stored cursor; got {:?}",
            adapter.sinces()
        );
        assert!(
            wait_until(|| action.applied() == vec!["pkg-after-recovery"]).await,
            "consumption resumes once the cursor is readable again"
        );
        cancel.cancel();
        handle.await.expect("join");
    }

    /// A lock wrapper counting acquire attempts, so term-end re-contention
    /// is observable without racing the release/re-acquire gap.
    #[derive(Clone)]
    struct CountingLock {
        inner: InMemoryClusterLock,
        acquires: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl ClusterLock for CountingLock {
        async fn try_acquire(
            &self,
            class: i32,
            obj: i32,
        ) -> crate::error::Result<Option<crate::services::cluster_lock::ClusterLease>> {
            self.acquires
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.try_acquire(class, obj).await
        }
    }

    #[tokio::test]
    async fn consumer_steps_down_at_term_end_and_recontends() {
        // A leader whose lock connection silently died can only discover it
        // by re-contending; the bounded term forces that periodically. The
        // leader is sticky (it re-acquires immediately), so the observable
        // signal is repeated acquire attempts, not a leadership gap.
        let lock = CountingLock {
            inner: InMemoryClusterLock::default(),
            acquires: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        let adapter = ScriptedAdapter::new(vec![batch(&["pkg-a"], "1")]);
        let action = Arc::new(RecordingAction::default());
        let cancel = CancellationToken::new();
        let consumer = FeedConsumer::new(
            adapter.clone(),
            action.clone(),
            Arc::new(MemoryStateStore::default()),
            Arc::new(lock.clone()),
            cancel.clone(),
        )
        .with_timings(
            Duration::from_millis(10),
            Duration::from_millis(30),
            Duration::from_millis(10),
            Duration::from_millis(40),
        );
        let handle = tokio::spawn(consumer.run());

        assert!(
            wait_until(|| !action.applied().is_empty()).await,
            "the consumer leads and consumes initially"
        );
        let acquires = lock.acquires.clone();
        assert!(
            wait_until(move || acquires.load(std::sync::atomic::Ordering::SeqCst) >= 3).await,
            "the leader must step down at term end and re-contend the lock \
             (this is what bounds dual consumption after a silent lock loss)"
        );
        cancel.cancel();
        handle.await.expect("join");
    }

    #[tokio::test]
    async fn consumer_stops_promptly_on_cancellation() {
        let adapter = ScriptedAdapter::new(vec![]);
        let cancel = CancellationToken::new();
        let consumer = test_consumer(
            adapter,
            Arc::new(RecordingAction::default()),
            Arc::new(MemoryStateStore::default()),
            Arc::new(InMemoryClusterLock::default()),
            cancel.clone(),
        );
        let handle = tokio::spawn(consumer.run());
        tokio::time::sleep(Duration::from_millis(30)).await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("the consumer must stop promptly on cancellation")
            .expect("join");
    }

    // -- DB-gated integration (skips without DATABASE_URL) -----------------------

    #[tokio::test]
    async fn pg_feed_state_store_round_trips() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let store = PgFeedStateStore::new(pool.clone());
        let feed_key = format!("it-feed-{}", uuid::Uuid::new_v4().simple());

        assert_eq!(store.load(&feed_key).await.expect("load empty"), None);
        store.save(&feed_key, "100").await.expect("insert");
        assert_eq!(
            store.load(&feed_key).await.expect("load"),
            Some("100".to_string())
        );
        store.save(&feed_key, "200-abc").await.expect("upsert");
        assert_eq!(
            store.load(&feed_key).await.expect("reload"),
            Some("200-abc".to_string())
        );

        sqlx::query("DELETE FROM upstream_feed_state WHERE feed_key = $1")
            .bind(&feed_key)
            .execute(&pool)
            .await
            .expect("cleanup");
    }

    #[tokio::test]
    async fn invalidation_action_scopes_to_covered_repos_and_their_virtuals() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let covered_id = uuid::Uuid::new_v4();
        let covered_key = format!("npm-remote-{suffix}");
        let other_id = uuid::Uuid::new_v4();
        let other_key = format!("npm-private-{suffix}");
        let virtual_id = uuid::Uuid::new_v4();
        let virtual_key = format!("npm-virtual-{suffix}");
        for (id, key, repo_type, upstream) in [
            (
                covered_id,
                &covered_key,
                "remote",
                Some("https://registry.npmjs.org"),
            ),
            (
                other_id,
                &other_key,
                "remote",
                Some("https://verdaccio.internal.example"),
            ),
            (virtual_id, &virtual_key, "virtual", None),
        ] {
            sqlx::query(&format!(
                "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, upstream_url) \
                 VALUES ($1, $2, $3, $4, '{repo_type}'::repository_type, 'npm'::repository_format, $5)"
            ))
            .bind(id)
            .bind(key)
            .bind(key)
            .bind(format!("/tmp/{key}"))
            .bind(upstream)
            .execute(&pool)
            .await
            .expect("seed repo");
        }
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 1)",
        )
        .bind(virtual_id)
        .bind(covered_id)
        .execute(&pool)
        .await
        .expect("seed virtual member");

        // Warm cache entries for the changed package in all three repos, and
        // for an unrelated package in the covered repo.
        let cache = Arc::new(NpmPackumentCache::new(
            Arc::new(
                crate::services::npm_packument_cache::InProcessPackumentCache::new(
                    Duration::from_secs(3600),
                ),
            ),
            Duration::from_secs(300),
        ));
        let entry = crate::services::npm_packument_cache::CachedPackument {
            bytes: bytes::Bytes::from_static(b"{}"),
            content_type: "application/json".to_string(),
            content_encoding: None,
        };
        let base = "https://ak.example.test";
        let changed = |repo: &str| {
            crate::services::npm_packument_cache::cache_key(repo, "left-pad", false, false, base)
        };
        for repo in [&covered_key, &other_key, &virtual_key] {
            cache.store(&changed(repo), entry.clone()).await;
        }
        let unrelated_key = crate::services::npm_packument_cache::cache_key(
            &covered_key,
            "unrelated-pkg",
            false,
            false,
            base,
        );
        cache.store(&unrelated_key, entry.clone()).await;

        let action = PackumentInvalidationAction::new(pool.clone(), cache.clone());
        action
            .apply(&[FeedEvent {
                package: "left-pad".to_string(),
            }])
            .await;

        assert!(
            cache.lookup(&changed(&covered_key)).await.is_none(),
            "the covered remote repo must be invalidated"
        );
        assert!(
            cache.lookup(&changed(&virtual_key)).await.is_none(),
            "virtual repos containing the covered remote must be invalidated"
        );
        assert!(
            cache.lookup(&changed(&other_key)).await.is_some(),
            "repos proxying other upstreams are outside the feed's scope"
        );
        assert!(
            cache.lookup(&unrelated_key).await.is_some(),
            "other packages in the covered repo must survive"
        );

        sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
            .bind(virtual_id)
            .execute(&pool)
            .await
            .expect("cleanup members");
        sqlx::query("DELETE FROM repositories WHERE id = ANY($1)")
            .bind(vec![covered_id, other_id, virtual_id])
            .execute(&pool)
            .await
            .expect("cleanup repos");
    }
}
