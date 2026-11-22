//! Re-catalog sweep for proxy-cache entries that have no catalog row (#6429).
//!
//! A proxy-cache fill writes its content object, then its sidecar
//! (`__cache_meta__.json`), then its `proxy_cache_artifacts` row. The row can
//! be missing while both objects are present: the catalog write is
//! best-effort, and since #5635 it commits asynchronously by default, so a
//! database crash or failover can lose the rows of the last few fills. Such an
//! entry is still served, but its bytes are missing from the Remote's
//! `proxy_bytes` (quota and cache cap), eviction does not see it, and neither
//! does the periodic re-scan. Before this sweep only a later read restored the
//! row (the lazy backfill on a cache hit).
//!
//! # What a pass does
//!
//! For each Remote, in id order, it lists the Remote's cache tree under this
//! deployment's scope one page at a time ([`StorageBackend::list_page`]) and,
//! for each sidecar whose content key has no catalog row, writes the row from
//! the sidecar through [`proxy_catalog::backfill_from_sidecar_returning`]: the
//! lazy backfill's statement, with its placeholder-only conflict guard, so a
//! row a concurrent fill writes is never overwritten. The content object is
//! never read; its existence is checked.
//!
//! # What it never re-catalogs
//!
//! * A negative-cache sidecar (a cached upstream 404) or one whose content
//!   object is gone.
//! * A sidecar written less than `PROXY_CACHE_RECATALOG_MIN_AGE_SECS` ago: its
//!   fill may still be committing its own row.
//! * A sidecar written before its Remote was created: it was left by a
//!   deleted repository that had the same key.
//! * An entry an `artifacts` row with the same storage key marks as deleted
//!   (in the trash) or rejected: an operator removed it.
//! * An entry purged while the sweep wrote its row. Invalidation deletes the
//!   objects before the row, and the sweep re-checks the sidecar after its
//!   insert and takes back a row it inserted for an entry that is gone.
//!
//! A held entry keeps its hold: the row takes the sidecar's
//! `quarantine_until`, as the lazy backfill does. The sweep never serves or
//! gates anything: the serve paths read the sidecar, not this table.
//!
//! # Cost and safety
//!
//! A pass lists at most `PROXY_CACHE_RECATALOG_BUDGET` keys, `PAGE_SIZE` per
//! listing call with a pause between pages, and resumes where the previous
//! pass on this replica stopped. Per page it runs one catalog query; the
//! sidecar and existence reads and the artifacts check happen only for keys
//! with no row. It runs on one replica at a time under a scheduler lease,
//! renewed for the whole pass; a lost lease stops it between pages.
//!
//! `PROXY_CACHE_RECATALOG_INTERVAL_SECS` sets the period (default six hours,
//! first pass a few minutes after startup); `0` or `off` turns it off.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::metrics_service;
use crate::services::proxy_cache_scope::ProxyCacheScope;
use crate::services::proxy_catalog;
use crate::services::proxy_service::{CacheKeys, CacheMetadata};
use crate::services::storage_service::StorageBackend;

/// Environment variable holding the pass interval in seconds.
pub const INTERVAL_ENV: &str = "PROXY_CACHE_RECATALOG_INTERVAL_SECS";
/// Environment variable holding the number of keys one pass may list.
pub const BUDGET_ENV: &str = "PROXY_CACHE_RECATALOG_BUDGET";
/// Environment variable holding the minimum sidecar age, in seconds.
pub const MIN_AGE_ENV: &str = "PROXY_CACHE_RECATALOG_MIN_AGE_SECS";
/// Scheduler lease name; one replica runs a pass at a time.
pub const LEASE_NAME: &str = "proxy_cache_recatalog";
/// Lease TTL, renewed for as long as a pass runs.
pub const LEASE_TTL_SECS: f64 = 600.0;
/// The default interval between passes.
pub const DEFAULT_INTERVAL_SECS: u64 = 6 * 3600;
/// The shortest interval accepted; a smaller value is raised to it.
pub const MIN_INTERVAL_SECS: u64 = 10;
/// The longest delay before the first pass after startup.
pub const MAX_STARTUP_DELAY_SECS: u64 = 300;
/// The default number of keys one pass may list.
pub const DEFAULT_BUDGET: usize = 100_000;
/// The default minimum sidecar age.
pub const DEFAULT_MIN_AGE_SECS: i64 = 600;
/// Keys per listing call.
pub const PAGE_SIZE: usize = 1000;
/// Pause between listing calls, so a pass never runs storage or the pool hot.
pub const PAGE_PAUSE: Duration = Duration::from_millis(50);
/// Consecutive failed re-catalog writes after which a pass stops.
const MAX_CONSECUTIVE_FAILURES: u32 = 20;

/// The sweep's settings ([`SweepConfig::from_env`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepConfig {
    /// Time between passes; `None` turns the sweep off.
    pub interval: Option<Duration>,
    /// Keys one pass may list.
    pub budget: usize,
    /// Sidecars younger than this are left to their own fill.
    pub min_age_secs: i64,
    /// Keys per listing call.
    pub page_size: usize,
    /// Pause between listing calls.
    pub page_pause: Duration,
}

impl SweepConfig {
    /// The settings from the environment.
    pub fn from_env() -> Self {
        let var = |name| std::env::var(name).ok();
        Self::from_values(
            var(INTERVAL_ENV).as_deref(),
            var(BUDGET_ENV).as_deref(),
            var(MIN_AGE_ENV).as_deref(),
        )
    }

    /// The settings for these variable values. An unset or unparsable value
    /// takes its default; an interval of `0`, `off`, `false` or `no` turns the
    /// sweep off.
    pub fn from_values(
        interval: Option<&str>,
        budget: Option<&str>,
        min_age: Option<&str>,
    ) -> Self {
        let interval = match interval.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
            Some("0" | "off" | "false" | "no") => None,
            Some(v) => Some(v.parse::<u64>().unwrap_or(DEFAULT_INTERVAL_SECS)),
            None => Some(DEFAULT_INTERVAL_SECS),
        }
        .map(|secs| Duration::from_secs(secs.max(MIN_INTERVAL_SECS)));
        let budget = budget
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|b| *b > 0)
            .unwrap_or(DEFAULT_BUDGET);
        let min_age_secs = min_age
            .and_then(|v| v.trim().parse::<i64>().ok())
            .filter(|s| *s >= 0)
            .unwrap_or(DEFAULT_MIN_AGE_SECS);
        Self {
            interval,
            budget,
            min_age_secs,
            page_size: PAGE_SIZE,
            page_pause: PAGE_PAUSE,
        }
    }

    /// The delay before the first pass: the interval, at most
    /// [`MAX_STARTUP_DELAY_SECS`].
    pub fn startup_delay_secs(&self) -> u64 {
        self.interval
            .map_or(0, |i| i.as_secs().min(MAX_STARTUP_DELAY_SECS))
    }

    /// The line logged once at startup.
    pub fn startup_message(&self) -> String {
        match self.interval {
            None => format!("Proxy-cache re-catalog sweep is off ({INTERVAL_ENV}=0)"),
            Some(i) => format!(
                "Proxy-cache re-catalog sweep: every {} s, up to {} keys a pass, sidecars older \
                 than {} s ({INTERVAL_ENV}=0 turns it off)",
                i.as_secs(),
                self.budget,
                self.min_age_secs
            ),
        }
    }
}

/// What one pass did. Every counter is also exported as
/// `ak_proxy_cache_recatalog_total{outcome}`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SweepReport {
    /// Remotes whose listing the pass started.
    pub remotes: u64,
    /// Keys listed.
    pub scanned: u64,
    /// Entry sidecars among them.
    pub sidecars: u64,
    /// Rows written.
    pub recataloged: u64,
    /// Bytes those rows put back on their Remotes' ledgers.
    pub recataloged_bytes: u64,
    /// Sidecars skipped, by reason ([`Skip`]).
    pub skipped_negative: u64,
    pub skipped_young: u64,
    pub skipped_stale: u64,
    pub skipped_no_content: u64,
    pub skipped_unreadable: u64,
    pub skipped_deleted: u64,
    /// The sidecar had a row by the time the sweep wrote one (a concurrent
    /// fill or serve), so nothing was inserted.
    pub met_row: u64,
    /// Rows inserted for an entry purged meanwhile, and taken back.
    pub raced: u64,
    /// Re-catalog writes that failed.
    pub failed: u64,
    /// Whether the pass reached the end of the last Remote's listing.
    pub complete: bool,
    /// Whether a lost lease stopped the pass.
    pub interrupted: bool,
    /// How long the pass took.
    pub elapsed_ms: u64,
}

impl SweepReport {
    fn record_metrics(&self) {
        for (outcome, n) in [
            ("scanned", self.scanned),
            ("recataloged", self.recataloged),
            ("skipped_negative", self.skipped_negative),
            ("skipped_young", self.skipped_young),
            ("skipped_stale", self.skipped_stale),
            ("skipped_no_content", self.skipped_no_content),
            ("skipped_unreadable", self.skipped_unreadable),
            ("skipped_deleted", self.skipped_deleted),
            ("met_row", self.met_row),
            ("raced", self.raced),
            ("failed", self.failed),
        ] {
            if n > 0 {
                metrics_service::record_proxy_cache_recatalog(outcome, n);
            }
        }
        if self.recataloged_bytes > 0 {
            metrics_service::record_proxy_cache_recatalog_bytes(self.recataloged_bytes);
        }
    }

    fn count_skip(&mut self, skip: Skip) {
        let counter = match skip {
            Skip::Negative => &mut self.skipped_negative,
            Skip::Young => &mut self.skipped_young,
            Skip::Stale => &mut self.skipped_stale,
        };
        *counter += 1;
    }
}

/// Why a sidecar with no row is not re-cataloged, decided from the sidecar
/// alone ([`sidecar_skip`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// A cached upstream 404: there is no body to account for.
    Negative,
    /// Written less than the minimum age ago; its fill may still be writing
    /// its own row.
    Young,
    /// Written before the Remote was created: a leftover of a deleted
    /// repository with the same key.
    Stale,
}

/// Whether a sidecar is left alone, from what it records.
pub fn sidecar_skip(
    meta: &CacheMetadata,
    now: DateTime<Utc>,
    min_age_secs: i64,
    remote_created_at: DateTime<Utc>,
) -> Option<Skip> {
    if meta.negative_cached_until.is_some() {
        Some(Skip::Negative)
    } else if meta.cached_at < remote_created_at {
        Some(Skip::Stale)
    } else if meta.cached_at > now - chrono::Duration::seconds(min_age_secs) {
        Some(Skip::Young)
    } else {
        None
    }
}

/// One cache entry a listing names: its logical path and both keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedEntry {
    pub path: String,
    pub content_key: String,
    pub metadata_key: String,
}

/// The entries whose sidecars `keys` lists for `repo_key`: each
/// `<repo_root><path>/__cache_meta__.json` whose path derives exactly that key
/// again ([`CacheKeys::derive`]). Bodies, staging files and anything not in
/// the derived shape are left out.
pub fn listed_entries(
    scope: &ProxyCacheScope,
    repo_key: &str,
    keys: &[String],
) -> Vec<ListedEntry> {
    let root = scope.repo_root(repo_key);
    keys.iter()
        .filter_map(|key| {
            let path = key
                .strip_prefix(&root)?
                .strip_suffix("/__cache_meta__.json")?;
            let derived = CacheKeys::derive(scope, repo_key, path).ok()?;
            (derived.metadata == *key).then(|| ListedEntry {
                path: path.to_string(),
                content_key: derived.content,
                metadata_key: derived.metadata,
            })
        })
        .collect()
}

/// A Remote as a pass visits it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Remote {
    pub id: Uuid,
    pub key: String,
    pub created_at: DateTime<Utc>,
}

/// How [`RecatalogSweep::sweep_remote`] left a Remote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteSweep {
    /// Its listing is done.
    Done,
    /// The budget ran out, the lease was lost or too many writes failed; the
    /// next pass resumes from this cursor (`None`: from the Remote's start).
    Stopped(Option<String>),
}

/// Where the next pass on this replica picks up.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Position {
    remote: Option<Uuid>,
    cursor: Option<String>,
}

/// The sweep: its handles, settings and resume position.
pub struct RecatalogSweep {
    db: PgPool,
    storage: Arc<dyn StorageBackend>,
    scope: ProxyCacheScope,
    config: SweepConfig,
    position: Mutex<Position>,
}

impl RecatalogSweep {
    /// A sweep over the proxy cache that `storage` holds under `scope`.
    pub fn new(
        db: PgPool,
        storage: Arc<dyn StorageBackend>,
        scope: ProxyCacheScope,
        config: SweepConfig,
    ) -> Self {
        Self {
            db,
            storage,
            scope,
            config,
            position: Mutex::new(Position::default()),
        }
    }

    /// The settings in force.
    pub fn config(&self) -> &SweepConfig {
        &self.config
    }

    /// One pass over every Remote, from where the last pass stopped, within
    /// the key budget. `lost` stops it between pages.
    pub async fn run_pass(&self, lost: Option<&CancellationToken>) -> Result<SweepReport> {
        let started = std::time::Instant::now();
        let start = self.position.lock().map(|p| p.clone()).unwrap_or_default();
        let remotes: Vec<Remote> = sqlx::query_as(
            "SELECT id, key, created_at FROM repositories \
             WHERE repo_type = 'remote'::repository_type AND id >= $1 ORDER BY id",
        )
        .bind(start.remote.unwrap_or(Uuid::nil()))
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let mut report = SweepReport::default();
        let mut budget = self.config.budget;
        let mut next = Position::default();
        for remote in &remotes {
            let cursor = (start.remote == Some(remote.id))
                .then(|| start.cursor.clone())
                .flatten();
            report.remotes += 1;
            let outcome = self
                .sweep_remote(remote, cursor, &mut budget, &mut report, lost)
                .await?;
            if let RemoteSweep::Stopped(cursor) = outcome {
                next = Position {
                    remote: Some(remote.id),
                    cursor,
                };
                break;
            }
        }
        report.complete = next == Position::default();
        report.elapsed_ms = started.elapsed().as_millis() as u64;
        if let Ok(mut position) = self.position.lock() {
            *position = next;
        }
        report.record_metrics();
        Ok(report)
    }

    /// Sweep one Remote from `cursor` (`None`: from its first key).
    pub async fn sweep_remote(
        &self,
        remote: &Remote,
        mut cursor: Option<String>,
        budget: &mut usize,
        report: &mut SweepReport,
        lost: Option<&CancellationToken>,
    ) -> Result<RemoteSweep> {
        let root = self.scope.repo_root(&remote.key);
        let mut failures = 0u32;
        loop {
            if lost.is_some_and(|t| t.is_cancelled()) {
                report.interrupted = true;
                return Ok(RemoteSweep::Stopped(cursor));
            }
            if *budget == 0 {
                return Ok(RemoteSweep::Stopped(cursor));
            }
            let limit = self.config.page_size.min(*budget);
            let page = self
                .storage
                .list_page(&root, cursor.as_deref(), limit)
                .await?;
            *budget = budget.saturating_sub(page.keys.len());
            report.scanned += page.keys.len() as u64;
            let entries = listed_entries(&self.scope, &remote.key, &page.keys);
            report.sidecars += entries.len() as u64;
            failures = self
                .recatalog_page(remote, entries, report, failures)
                .await?;
            if failures >= MAX_CONSECUTIVE_FAILURES {
                tracing::warn!(
                    repository = %remote.key,
                    failures,
                    "proxy-cache re-catalog: stopping the pass after repeated write failures"
                );
                return Ok(RemoteSweep::Stopped(page.next.or(cursor)));
            }
            match page.next {
                Some(next) => cursor = Some(next),
                None => return Ok(RemoteSweep::Done),
            }
            tokio::time::sleep(self.config.page_pause).await;
        }
    }

    /// Re-catalog the entries of one page that have no row. Returns the
    /// running count of consecutive failed writes.
    async fn recatalog_page(
        &self,
        remote: &Remote,
        entries: Vec<ListedEntry>,
        report: &mut SweepReport,
        mut failures: u32,
    ) -> Result<u32> {
        if entries.is_empty() {
            return Ok(failures);
        }
        let content_keys: Vec<&str> = entries.iter().map(|e| e.content_key.as_str()).collect();
        let cataloged: Vec<String> = sqlx::query_scalar(
            "SELECT storage_key FROM proxy_cache_artifacts WHERE storage_key = ANY($1)",
        )
        .bind(&content_keys)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        let missing: Vec<ListedEntry> = entries
            .into_iter()
            .filter(|e| !cataloged.contains(&e.content_key))
            .collect();
        if missing.is_empty() {
            return Ok(failures);
        }
        let missing_keys: Vec<&str> = missing.iter().map(|e| e.content_key.as_str()).collect();
        // An operator removed these: a trashed or rejected `artifacts` row (a
        // pre-1.2.0 proxy row) on the same object.
        let removed: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT storage_key FROM artifacts \
             WHERE repository_id = $1 AND storage_key = ANY($2) \
               AND (is_deleted OR quarantine_status = 'rejected')",
        )
        .bind(remote.id)
        .bind(&missing_keys)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        for entry in missing {
            if removed.contains(&entry.content_key) {
                report.skipped_deleted += 1;
                continue;
            }
            match self.recatalog_entry(remote, &entry, report).await {
                Ok(()) => failures = 0,
                Err(e) => {
                    report.failed += 1;
                    failures += 1;
                    tracing::warn!(
                        repository = %remote.key,
                        path = %entry.path,
                        error = %e,
                        "proxy-cache re-catalog: could not write the entry's row"
                    );
                    if failures >= MAX_CONSECUTIVE_FAILURES {
                        break;
                    }
                }
            }
        }
        Ok(failures)
    }

    /// Re-catalog one entry with no row from its sidecar.
    async fn recatalog_entry(
        &self,
        remote: &Remote,
        entry: &ListedEntry,
        report: &mut SweepReport,
    ) -> Result<()> {
        let Some(meta) = self.read_sidecar(&entry.metadata_key).await? else {
            report.skipped_unreadable += 1;
            return Ok(());
        };
        if let Some(skip) = sidecar_skip(
            &meta,
            Utc::now(),
            self.config.min_age_secs,
            remote.created_at,
        ) {
            report.count_skip(skip);
            return Ok(());
        }
        if !self.storage.exists(&entry.content_key).await? {
            report.skipped_no_content += 1;
            return Ok(());
        }
        let row = proxy_catalog::backfill_from_sidecar_returning(
            &self.db,
            remote.id,
            &entry.path,
            &entry.content_key,
            &entry.metadata_key,
            meta.size_bytes,
            Some(meta.checksum_sha256.as_str()),
            meta.content_type.as_deref(),
            meta.quarantine_until,
        )
        .await?;
        if !row.inserted {
            report.met_row += 1;
            return Ok(());
        }
        // Purged while the row was written: invalidation deletes the objects
        // before the row, so a sidecar gone now means the row just inserted
        // describes nothing. Take it back.
        if !self.storage.exists(&entry.metadata_key).await? {
            proxy_catalog::delete_backfilled(&self.db, &row).await?;
            report.raced += 1;
            return Ok(());
        }
        report.recataloged += 1;
        report.recataloged_bytes += meta.size_bytes.max(0) as u64;
        tracing::debug!(
            repository = %remote.key,
            path = %entry.path,
            size_bytes = meta.size_bytes,
            "proxy-cache re-catalog: restored the entry's catalog row"
        );
        Ok(())
    }

    /// The sidecar at `key`, or `None` when it is gone or does not parse.
    async fn read_sidecar(&self, key: &str) -> Result<Option<CacheMetadata>> {
        match self.storage.get(key).await {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
            Err(AppError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Log one pass's outcome: `info` when it changed something, `debug`
/// otherwise.
pub fn log_pass(report: &SweepReport) {
    if report.recataloged > 0 || report.raced > 0 || report.failed > 0 {
        tracing::info!(
            remotes = report.remotes,
            scanned = report.scanned,
            sidecars = report.sidecars,
            recataloged = report.recataloged,
            recataloged_bytes = report.recataloged_bytes,
            skipped_deleted = report.skipped_deleted,
            skipped_negative = report.skipped_negative,
            skipped_young = report.skipped_young,
            skipped_stale = report.skipped_stale,
            skipped_no_content = report.skipped_no_content,
            skipped_unreadable = report.skipped_unreadable,
            met_row = report.met_row,
            raced = report.raced,
            failed = report.failed,
            complete = report.complete,
            interrupted = report.interrupted,
            elapsed_ms = report.elapsed_ms,
            "Proxy-cache re-catalog pass"
        );
    } else {
        tracing::debug!(
            remotes = report.remotes,
            scanned = report.scanned,
            sidecars = report.sidecars,
            complete = report.complete,
            interrupted = report.interrupted,
            elapsed_ms = report.elapsed_ms,
            "Proxy-cache re-catalog pass: nothing to restore"
        );
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests;
