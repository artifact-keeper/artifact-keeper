//! Bounding the virtual conda merge (#4608).
//!
//! A merged virtual document (`repodata.json` in every encoding,
//! `channeldata.json`, the CEP-16 shard index) is rebuilt from its members,
//! and a conda-forge subdir makes that expensive: the member document decodes
//! to several hundred MiB of JSON and the merge writes a document of the same
//! order. Built once per request, N concurrent solves cost N times that at
//! once, which is how a cold-cache CI burst took the backend past 20 GiB and
//! into the OOM killer. Three things bound it here:
//!
//! 1. **Singleflight and a short-lived cache.** Requests for the same merged
//!    document share one merge, and its result is kept (as served, already
//!    encoded) for `CONDA_VIRTUAL_MERGE_CACHE_TTL_SECS` and served with one
//!    ETag, so revalidation answers 304. The key is a digest of every input
//!    the merge reads that can change without a member refetch: the virtual,
//!    the document and encoding, the caller-visible member set, the hosted
//!    records and the names hosted members own, and the allowlist's stored
//!    value. Remote members are covered by validators instead: the merge
//!    records the SHA-256 of each member document it read, and a cached
//!    merge is served only while each member's proxy-cache entry is still
//!    fresh and still holds those bytes, which is exactly when a rebuild
//!    would read the same bytes without contacting the upstream. The name
//!    guard, the allowlist and member fetch failures are evaluated inside the
//!    one merge; a merge with a failed member is never cached, and the
//!    failure policy (#4192) is applied to each response as before.
//! 2. **A cap on concurrent merges.** At most
//!    `CONDA_VIRTUAL_MAX_CONCURRENT_MERGES` run at once across all virtuals; a
//!    merge waits up to `CONDA_VIRTUAL_MERGE_QUEUE_SECS` for a slot and then
//!    answers 503 with `Retry-After`, which conda clients retry.
//! 3. **Accounting against the buffered-metadata budget (#2684).** Before it
//!    fetches anything a merge reserves, from the process-wide budget
//!    (`AK_PROXY_METADATA_BUDGET_BYTES`), what the previous merge of the same
//!    document held at most (member fetch buffer, decoded member documents,
//!    working set and output) plus a margin, or the whole budget the first
//!    time. The wait is bounded by the same queue deadline, and the merge
//!    never waits again while it holds budget ([`MergeAccount`]), so what
//!    the merges hold in flight is bounded by configuration and visible next
//!    to every other buffered-metadata reader.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures::future::{BoxFuture, FutureExt, Shared};
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::virtual_merge::{MemberFailure, MemberLimits};
use crate::api::handlers::proxy_helpers::{self, ProxyMetadataBudget};
use crate::services::metrics_service;

/// Most merges running at once, across every virtual conda channel.
pub(super) const MAX_CONCURRENT_MERGES_ENV: &str = "CONDA_VIRTUAL_MAX_CONCURRENT_MERGES";
/// Longest a merge waits for a slot, or for its share of the budget, before
/// the request is shed with 503.
pub(super) const MERGE_QUEUE_SECS_ENV: &str = "CONDA_VIRTUAL_MERGE_QUEUE_SECS";
/// How long a merged document is kept. `0` disables the cache (concurrent
/// requests still share one merge).
pub(super) const MERGE_CACHE_TTL_SECS_ENV: &str = "CONDA_VIRTUAL_MERGE_CACHE_TTL_SECS";
/// Ceiling on the bytes of merged documents kept by the cache.
pub(super) const MERGE_CACHE_MAX_BYTES_ENV: &str = "CONDA_VIRTUAL_MERGE_CACHE_MAX_BYTES";

const DEFAULT_QUEUE_SECS: u64 = 60;
/// The proxy cache's default TTL for mutable metadata, which is what a
/// remote member's repodata is cached under.
const DEFAULT_CACHE_TTL_SECS: u64 =
    crate::services::cache_classifier::MUTABLE_DEFAULT_TTL_SECS.unsigned_abs();
const DEFAULT_CACHE_MAX_BYTES: u64 = 1024 * 1024 * 1024;
/// A solve fetches its platform subdir and `noarch` together, so two merges
/// may always run side by side; the budget still bounds their bytes.
const MIN_DEFAULT_MERGES: usize = 2;
/// `Retry-After` on a shed merge, capped by the queue deadline.
const RETRY_AFTER_SECS: u64 = 5;

/// What a merge builds; the `kind` label on the merge metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MergeKind {
    Repodata,
    Channeldata,
    ShardIndex,
}

impl MergeKind {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Repodata => "repodata",
            Self::Channeldata => "channeldata",
            Self::ShardIndex => "shard_index",
        }
    }
}

/// The gate's settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct GateConfig {
    pub max_merges: usize,
    pub queue_wait: Duration,
    pub cache_ttl: Duration,
    pub cache_max_bytes: u64,
}

impl GateConfig {
    /// Default merge cap: as many merges as the budget holds at the member
    /// ceilings (one fetch buffer plus one decoded document each), and never
    /// fewer than two.
    pub(super) fn default_max_merges(budget_total: usize, limits: MemberLimits) -> usize {
        let per_merge = limits.fetched.saturating_add(limits.decoded).max(1);
        (budget_total / per_merge).max(MIN_DEFAULT_MERGES)
    }

    /// Read the settings through `get` (the environment in production). An
    /// unset or unparseable value takes the default; so does a zero merge cap
    /// or queue deadline, which would refuse every merge.
    pub(super) fn from_lookup(
        get: impl Fn(&str) -> Option<String>,
        budget_total: usize,
        limits: MemberLimits,
    ) -> Self {
        let num = |key: &str| get(key).and_then(|v| v.trim().parse::<u64>().ok());
        Self {
            max_merges: num(MAX_CONCURRENT_MERGES_ENV)
                .filter(|v| *v > 0)
                .map_or_else(
                    || Self::default_max_merges(budget_total, limits),
                    |v| usize::try_from(v).unwrap_or(usize::MAX),
                )
                .min(Semaphore::MAX_PERMITS),
            queue_wait: Duration::from_secs(
                num(MERGE_QUEUE_SECS_ENV)
                    .filter(|v| *v > 0)
                    .unwrap_or(DEFAULT_QUEUE_SECS),
            ),
            cache_ttl: Duration::from_secs(
                num(MERGE_CACHE_TTL_SECS_ENV).unwrap_or(DEFAULT_CACHE_TTL_SECS),
            ),
            cache_max_bytes: num(MERGE_CACHE_MAX_BYTES_ENV).unwrap_or(DEFAULT_CACHE_MAX_BYTES),
        }
    }

    fn retry_after_secs(&self) -> u64 {
        self.queue_wait.as_secs().clamp(1, RETRY_AFTER_SECS)
    }
}

/// Builds a merge key: a SHA-256 over length-prefixed parts, so no two
/// different part sequences collide by concatenation.
pub(super) struct MergeKeyBuilder(Sha256);

impl MergeKeyBuilder {
    pub(super) fn new(kind: MergeKind) -> Self {
        let mut b = Self(Sha256::new());
        b.part(kind.label().as_bytes());
        b
    }

    pub(super) fn part(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.update((bytes.len() as u64).to_le_bytes());
        self.0.update(bytes);
        self
    }

    pub(super) fn finish(self) -> String {
        hex::encode(self.0.finalize())
    }
}

/// The member document a merge read, by the SHA-256 of the bytes it read out
/// of that member's proxy cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MemberValidator {
    pub member: String,
    pub path: String,
    pub checksum: String,
}

/// What a merge held, for the budget-coverage contract.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct MergeStats {
    /// Decoded member documents, summed.
    pub decoded_bytes: usize,
    /// The merged document as served.
    pub output_bytes: usize,
    /// Budget bytes the merge held (its reservation, after any top-up).
    pub reserved: usize,
    /// The most the merge held at once by its own tracking.
    pub peak_need: usize,
}

/// A finished merge, shared by every request it answers.
pub(super) struct MergedDocument {
    pub body: Bytes,
    pub etag: String,
    pub failed: Vec<MemberFailure>,
    /// Remote records the allowlist left out; `None` when none is enforced.
    pub allowlist_dropped: Option<usize>,
    /// Every remote member's document, by checksum. Empty for a merge with no
    /// remote member.
    pub validators: Vec<MemberValidator>,
    /// Whether the document may be kept: no member failed and every remote
    /// member's document has a validator.
    pub cacheable: bool,
    pub stats: MergeStats,
    /// Whether the body is plain JSON (served gzip-coded on request).
    pub json: bool,
    /// The gzip rendering of a JSON body, built once on first demand.
    pub gzip: tokio::sync::OnceCell<Bytes>,
    /// For a shard index merge: where every listed shard comes from, so a
    /// shard request is routed from the kept merge (#4607).
    pub shard_index: Option<super::VirtualShardIndex>,
}

impl MergedDocument {
    pub(super) fn new(
        body: Vec<u8>,
        failed: Vec<MemberFailure>,
        allowlist_dropped: Option<usize>,
        validators: Vec<MemberValidator>,
        all_members_validated: bool,
        stats: MergeStats,
        json: bool,
    ) -> Self {
        let body = Bytes::from(body);
        let etag = crate::api::handlers::cache_headers::compute_etag(&body);
        let cacheable = failed.is_empty() && all_members_validated;
        Self {
            body,
            etag,
            failed,
            allowlist_dropped,
            validators,
            cacheable,
            stats,
            json,
            gzip: tokio::sync::OnceCell::new(),
            shard_index: None,
        }
    }

    /// Attach the shard routing of a shard index merge.
    pub(super) fn with_shard_index(mut self, shard_index: super::VirtualShardIndex) -> Self {
        self.shard_index = Some(shard_index);
        self
    }

    /// Cache weight in bytes: the body, plus room for the gzip rendering a
    /// JSON body may grow.
    fn weight(&self) -> u32 {
        let extra = if self.json { self.body.len() / 4 } else { 0 };
        u32::try_from(self.body.len().saturating_add(extra)).unwrap_or(u32::MAX)
    }
}

/// A rendered error response that every request sharing a merge can replay.
/// Cheap to clone (one shared allocation).
#[derive(Clone)]
pub(super) struct SharedResponse(Arc<SharedResponseParts>);

struct SharedResponseParts {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl SharedResponse {
    async fn from_response(response: Response) -> Self {
        let (parts, body) = response.into_parts();
        // Error bodies are a line of text, read under a 1 MiB bound; a failure
        // to read one still keeps the status.
        #[allow(clippy::disallowed_methods)]
        let body = axum::body::to_bytes(body, 1024 * 1024)
            .await
            .unwrap_or_default();
        Self(Arc::new(SharedResponseParts {
            status: parts.status,
            headers: parts.headers,
            body,
        }))
    }

    fn internal(reason: impl std::fmt::Display) -> Self {
        tracing::error!("conda virtual merge task failed: {reason}");
        Self(Arc::new(SharedResponseParts {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"Internal server error"),
        }))
    }

    pub(super) fn into_response(self) -> Response {
        let mut response = (self.0.status, self.0.body.clone()).into_response();
        for (name, value) in &self.0.headers {
            response.headers_mut().insert(name.clone(), value.clone());
        }
        response
    }
}

pub(super) type MergeOutcome = Result<Arc<MergedDocument>, SharedResponse>;

/// 503 for a merge shed by the gate.
fn shed_response(retry_after_secs: u64, detail: String) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [
            (header::RETRY_AFTER, HeaderValue::from(retry_after_secs)),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        format!("{detail}; retry after {retry_after_secs} s"),
    )
        .into_response()
}

/// Budget bytes reserved by every running merge, for the gauge.
static RESERVED_BYTES: AtomicUsize = AtomicUsize::new(0);

fn reserved_add(bytes: usize) {
    let now = RESERVED_BYTES.fetch_add(bytes, Ordering::AcqRel) + bytes;
    metrics_service::set_conda_virtual_merge_bytes_reserved(now);
}

fn reserved_sub(bytes: usize) {
    let now = RESERVED_BYTES.fetch_sub(bytes, Ordering::AcqRel) - bytes;
    metrics_service::set_conda_virtual_merge_bytes_reserved(now);
}

/// One merge's share of the buffered-metadata budget.
///
/// A merge takes its reservation once, before it fetches anything, waiting at
/// most the queue deadline and otherwise shedding with 503. It is sized from
/// what the previous merge of the same document needed, plus a margin, or is
/// the whole budget the first time the document is merged (an oversized
/// reservation degrades to exclusive, as a single buffered fetch does).
///
/// While the merge runs it tracks what it holds: the member fetch buffer
/// until the document is decoded, each decoded member document, and its
/// working set and output. When that outgrows the reservation the merge tops
/// up WITHOUT waiting, and goes on over its reservation if the budget has no
/// room. A merge therefore never waits for budget while it holds some, so
/// two merges cannot each hold part of the budget and wait for the other's
/// (the hold-and-wait shape #4129 removed from the single-remote path); the
/// overshoot is bounded by how much the document grew since its previous
/// merge, and the next merge reserves the new size.
pub(super) struct MergeAccount {
    kind: MergeKind,
    budget: &'static ProxyMetadataBudget,
    wait: Duration,
    retry_after_secs: u64,
    permits: Vec<OwnedSemaphorePermit>,
    reserved: usize,
    need: usize,
    peak_need: usize,
}

/// Source of the zero-permit placeholder handed to a fetch whose buffer is
/// covered by the merge's own reservation.
fn placeholder_permit() -> OwnedSemaphorePermit {
    static EMPTY: OnceLock<Arc<Semaphore>> = OnceLock::new();
    Arc::clone(EMPTY.get_or_init(|| Arc::new(Semaphore::new(0))))
        .try_acquire_many_owned(0)
        .expect("acquiring zero permits always succeeds")
}

impl MergeAccount {
    pub(super) fn new(
        kind: MergeKind,
        budget: &'static ProxyMetadataBudget,
        wait: Duration,
        retry_after_secs: u64,
    ) -> Self {
        Self {
            kind,
            budget,
            wait,
            retry_after_secs,
            permits: Vec::new(),
            reserved: 0,
            need: 0,
            peak_need: 0,
        }
    }

    fn keep(&mut self, permit: OwnedSemaphorePermit, bytes: usize) {
        self.permits.push(permit);
        self.reserved += bytes;
        reserved_add(bytes);
    }

    /// Take the merge's reservation: `estimate` bytes, clamped to the budget,
    /// waiting at most the queue deadline.
    pub(super) async fn reserve(&mut self, estimate: usize) -> Result<(), Response> {
        let bytes = estimate.clamp(1, self.budget.total_bytes());
        let permit = tokio::time::timeout(self.wait, self.budget.reserve(bytes))
            .await
            .map_err(|_| {
                metrics_service::record_conda_virtual_merge_rejected(self.kind.label(), "budget");
                tracing::warn!(
                    kind = self.kind.label(),
                    bytes,
                    budget = self.budget.total_bytes(),
                    "conda virtual merge shed: the buffered-metadata budget stayed exhausted"
                );
                shed_response(
                    self.retry_after_secs,
                    format!(
                        "The buffered-metadata budget ({}) is exhausted by in-flight work; this \
                         virtual conda channel merge waited {} s ({MERGE_QUEUE_SECS_ENV})",
                        proxy_helpers::PROXY_METADATA_BUDGET_BYTES_ENV,
                        self.wait.as_secs()
                    ),
                )
            })?;
        self.keep(permit, bytes);
        Ok(())
    }

    /// A permit for a member fetch whose buffer this merge's reservation
    /// covers (it carries no budget of its own). Track the buffer with
    /// [`Self::track`] once its size is known.
    pub(super) fn fetch_permit(&self) -> OwnedSemaphorePermit {
        placeholder_permit()
    }

    /// The merge now holds `bytes` more; top the reservation up without
    /// waiting if that outgrows it.
    pub(super) fn track(&mut self, bytes: usize) {
        self.need = self.need.saturating_add(bytes);
        self.peak_need = self.peak_need.max(self.need);
        let total = self.budget.total_bytes();
        let short = self.need.min(total).saturating_sub(self.reserved);
        if short > 0 {
            if let Some(permit) = self.budget.try_reserve(short) {
                self.keep(permit, short);
            } else {
                tracing::debug!(
                    kind = self.kind.label(),
                    over = short,
                    "conda virtual merge outgrew its reservation and the budget has no room"
                );
            }
        }
    }

    /// The merge released `bytes` (a decoded fetch buffer).
    pub(super) fn release(&mut self, bytes: usize) {
        self.need = self.need.saturating_sub(bytes);
    }

    /// Budget bytes this merge holds (its reservation only grows).
    pub(super) fn reserved(&self) -> usize {
        self.reserved
    }

    /// The most this merge held at once, which sizes the next merge of the
    /// same document.
    pub(super) fn peak_need(&self) -> usize {
        self.peak_need
    }
}

impl Drop for MergeAccount {
    fn drop(&mut self) {
        reserved_sub(self.reserved);
    }
}

/// Next reservation for a document whose previous merge needed `peak` bytes.
fn learned_estimate(peak: usize) -> usize {
    const MARGIN_FLOOR: usize = 1024 * 1024;
    peak.saturating_add((peak / 10).max(MARGIN_FLOOR))
}

type InflightMerge = Shared<BoxFuture<'static, MergeOutcome>>;

/// Singleflight, cache, merge slots and budget accounting for virtual conda
/// merges. One per process ([`gate_for`]).
pub(super) struct MergeGate {
    config: GateConfig,
    budget: &'static ProxyMetadataBudget,
    slots: Arc<Semaphore>,
    cache: Option<moka::future::Cache<String, Arc<MergedDocument>>>,
    inflight: Mutex<HashMap<String, InflightMerge>>,
    /// What the last merge of each document needed, by document shape.
    learned: Mutex<HashMap<String, usize>>,
    running: AtomicUsize,
    merges_started: AtomicU64,
}

impl MergeGate {
    pub(super) fn new(config: GateConfig, budget: &'static ProxyMetadataBudget) -> Arc<Self> {
        let cache = (!config.cache_ttl.is_zero() && config.cache_max_bytes > 0).then(|| {
            moka::future::Cache::builder()
                .max_capacity(config.cache_max_bytes)
                .weigher(|_key: &String, doc: &Arc<MergedDocument>| doc.weight())
                .time_to_live(config.cache_ttl)
                .build()
        });
        tracing::info!(
            max_merges = config.max_merges,
            queue_secs = config.queue_wait.as_secs(),
            cache_ttl_secs = config.cache_ttl.as_secs(),
            cache_max_bytes = config.cache_max_bytes,
            budget_bytes = budget.total_bytes(),
            "conda virtual merge gate configured"
        );
        Arc::new(Self {
            config,
            budget,
            slots: Arc::new(Semaphore::new(config.max_merges)),
            cache,
            inflight: Mutex::new(HashMap::new()),
            learned: Mutex::new(HashMap::new()),
            running: AtomicUsize::new(0),
            merges_started: AtomicU64::new(0),
        })
    }

    /// The process-wide gate, configured from the environment against the
    /// process-wide buffered-metadata budget.
    fn global() -> Arc<Self> {
        static GATE: OnceLock<Arc<MergeGate>> = OnceLock::new();
        Arc::clone(GATE.get_or_init(|| {
            let budget = proxy_helpers::proxy_metadata_budget();
            let config = GateConfig::from_lookup(
                |k| std::env::var(k).ok(),
                budget.total_bytes(),
                MemberLimits::from_env(),
            );
            Self::new(config, budget)
        }))
    }

    /// Merges this gate has started (tests).
    #[cfg(test)]
    pub(super) fn merges_started(&self) -> u64 {
        self.merges_started.load(Ordering::Acquire)
    }

    /// Take every merge slot (tests): further merges queue.
    #[cfg(test)]
    pub(super) async fn hold_all_slots(&self) -> OwnedSemaphorePermit {
        Arc::clone(&self.slots)
            .acquire_many_owned(u32::try_from(self.config.max_merges).unwrap())
            .await
            .unwrap()
    }

    /// Serve the merged document `key` from the cache when `validate` accepts
    /// it, else join the merge already running for `key`, else run `merge`.
    ///
    /// `budget_shape` names the document for budget accounting (the same
    /// document across generations, e.g. virtual + subdir + encoding): a
    /// merge with one reserves from the buffered-metadata budget before it
    /// starts, sized from the previous merge of that shape. `None` for a merge
    /// whose fetches reserve their own budget (the shard index).
    ///
    /// The merge runs as its own task, so a client that disconnects does not
    /// cancel the work the other requests are waiting on.
    pub(super) async fn get_or_merge<V, VF, M, MF>(
        self: &Arc<Self>,
        kind: MergeKind,
        key: String,
        budget_shape: Option<String>,
        validate: V,
        merge: M,
    ) -> MergeOutcome
    where
        V: FnOnce(Arc<MergedDocument>) -> VF,
        VF: Future<Output = bool>,
        M: FnOnce(MergeAccount) -> MF + Send + 'static,
        MF: Future<Output = Result<MergedDocument, Response>> + Send + 'static,
    {
        if let Some(cache) = &self.cache {
            if let Some(hit) = cache.get(&key).await {
                if validate(Arc::clone(&hit)).await {
                    metrics_service::record_conda_virtual_merge_cache_hit(kind.label(), "cache");
                    return Ok(hit);
                }
                cache.invalidate(&key).await;
            }
        }

        let (merge_future, leader) = {
            let mut inflight = self.inflight.lock().unwrap_or_else(|p| p.into_inner());
            match inflight.get(&key) {
                Some(running) => (running.clone(), false),
                None => {
                    let gate = Arc::clone(self);
                    let task_key = key.clone();
                    let task = tokio::spawn(async move {
                        gate.lead(kind, task_key, budget_shape, merge).await
                    });
                    let shared = async move {
                        task.await
                            .unwrap_or_else(|e| Err(SharedResponse::internal(e)))
                    }
                    .boxed()
                    .shared();
                    inflight.insert(key, shared.clone());
                    (shared, true)
                }
            }
        };
        if leader {
            metrics_service::record_conda_virtual_merge_cache_miss(kind.label());
        } else {
            metrics_service::record_conda_virtual_merge_cache_hit(kind.label(), "singleflight");
        }
        merge_future.await
    }

    async fn lead<M, MF>(
        self: Arc<Self>,
        kind: MergeKind,
        key: String,
        budget_shape: Option<String>,
        merge: M,
    ) -> MergeOutcome
    where
        M: FnOnce(MergeAccount) -> MF,
        MF: Future<Output = Result<MergedDocument, Response>>,
    {
        let outcome = self.run(kind, budget_shape, merge).await;
        if let (Ok(doc), Some(cache)) = (&outcome, &self.cache) {
            if doc.cacheable {
                cache.insert(key.clone(), Arc::clone(doc)).await;
            }
        }
        // After the cache insert: a request arriving now finds one or the
        // other.
        self.inflight
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&key);
        outcome
    }

    async fn run<M, MF>(
        &self,
        kind: MergeKind,
        budget_shape: Option<String>,
        merge: M,
    ) -> MergeOutcome
    where
        M: FnOnce(MergeAccount) -> MF,
        MF: Future<Output = Result<MergedDocument, Response>>,
    {
        let retry_after = self.config.retry_after_secs();
        let slot = match tokio::time::timeout(
            self.config.queue_wait,
            Arc::clone(&self.slots).acquire_owned(),
        )
        .await
        {
            Ok(Ok(slot)) => slot,
            _ => {
                metrics_service::record_conda_virtual_merge_rejected(kind.label(), "queue");
                tracing::warn!(
                    kind = kind.label(),
                    max_merges = self.config.max_merges,
                    "conda virtual merge shed: no merge slot within the queue deadline"
                );
                return Err(SharedResponse::from_response(shed_response(
                    retry_after,
                    format!(
                        "Too many virtual conda channel merges are running (limit {}, \
                         {MAX_CONCURRENT_MERGES_ENV}); this one waited {} s \
                         ({MERGE_QUEUE_SECS_ENV})",
                        self.config.max_merges,
                        self.config.queue_wait.as_secs()
                    ),
                ))
                .await);
            }
        };
        let mut account = MergeAccount::new(kind, self.budget, self.config.queue_wait, retry_after);
        if let Some(shape) = &budget_shape {
            let learned = self
                .learned
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(shape)
                .copied();
            // First merge of this document: its size is unknown, so it
            // reserves the whole budget and runs alone.
            let estimate = learned.map_or(self.budget.total_bytes(), learned_estimate);
            if let Err(shed) = account.reserve(estimate).await {
                return Err(SharedResponse::from_response(shed).await);
            }
        }
        self.merges_started.fetch_add(1, Ordering::AcqRel);
        let running = self.running.fetch_add(1, Ordering::AcqRel) + 1;
        metrics_service::set_conda_virtual_merge_inflight(running);
        let result = merge(account).await;
        let running = self.running.fetch_sub(1, Ordering::AcqRel) - 1;
        metrics_service::set_conda_virtual_merge_inflight(running);
        drop(slot);
        match result {
            Ok(doc) => {
                if let Some(shape) = budget_shape {
                    self.learned
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(shape, doc.stats.peak_need);
                }
                tracing::info!(
                    kind = kind.label(),
                    decoded_bytes = doc.stats.decoded_bytes,
                    output_bytes = doc.stats.output_bytes,
                    reserved = doc.stats.reserved,
                    peak_need = doc.stats.peak_need,
                    failed_members = doc.failed.len(),
                    cacheable = doc.cacheable,
                    "conda virtual merge finished"
                );
                Ok(Arc::new(doc))
            }
            Err(response) => Err(SharedResponse::from_response(response).await),
        }
    }
}

#[cfg(test)]
static TEST_GATES: OnceLock<Mutex<HashMap<uuid::Uuid, Arc<MergeGate>>>> = OnceLock::new();

/// Use `gate` for the virtual `virtual_repo_id` instead of the process-wide
/// one (tests that need their own slots, deadline or counters).
#[cfg(test)]
pub(super) fn install_test_gate(virtual_repo_id: uuid::Uuid, gate: Arc<MergeGate>) {
    TEST_GATES
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .insert(virtual_repo_id, gate);
}

/// The gate merges of `virtual_repo_id` go through.
pub(super) fn gate_for(virtual_repo_id: uuid::Uuid) -> Arc<MergeGate> {
    #[cfg(test)]
    if let Some(gate) = TEST_GATES
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .get(&virtual_repo_id)
    {
        return Arc::clone(gate);
    }
    let _ = virtual_repo_id;
    MergeGate::global()
}

/// What a merge holds besides its decoded member documents, given their
/// size: the parsed record maps (about a quarter of the decoded JSON) and the
/// output allowance ([`merge_output_allowance`]). Tracked before the merge
/// runs; the actual output is reconciled afterwards.
pub(super) fn merge_working_set(decoded_bytes: usize, plain_json_output: bool) -> usize {
    const FLOOR: usize = 64 * 1024;
    (decoded_bytes / 4)
        .saturating_add(merge_output_allowance(decoded_bytes, plain_json_output))
        .saturating_add(FLOOR)
}

/// Allowance for the merged output: a pretty-printed JSON document is larger
/// than its input, a compressed one several times smaller.
pub(super) fn merge_output_allowance(decoded_bytes: usize, plain_json_output: bool) -> usize {
    if plain_json_output {
        decoded_bytes.saturating_mul(3) / 2
    } else {
        decoded_bytes / 4
    }
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn limits(fetched: usize, decoded: usize) -> MemberLimits {
        MemberLimits { fetched, decoded }
    }

    #[test]
    fn default_merge_cap_follows_the_budget_and_member_ceilings() {
        const MIB: usize = 1024 * 1024;
        // Defaults: 1 GiB budget, 128 MiB fetch + 1 GiB decoded ceilings.
        assert_eq!(
            GateConfig::default_max_merges(1024 * MIB, limits(128 * MIB, 1024 * MIB)),
            2
        );
        // A budget sized for five merges at the ceilings allows five.
        assert_eq!(
            GateConfig::default_max_merges(5 * 1152 * MIB, limits(128 * MIB, 1024 * MIB)),
            5
        );
    }

    #[test]
    fn settings_parse_and_fall_back() {
        let budget = 1024 * 1024 * 1024;
        let l = limits(128 << 20, 1 << 30);
        let cfg = GateConfig::from_lookup(|_| None, budget, l);
        assert_eq!(cfg.max_merges, 2);
        assert_eq!(cfg.queue_wait, Duration::from_secs(60));
        assert_eq!(cfg.cache_ttl, Duration::from_secs(300));
        assert_eq!(cfg.cache_max_bytes, 1 << 30);

        let set = |k: &str| match k {
            MAX_CONCURRENT_MERGES_ENV => Some("7".to_string()),
            MERGE_QUEUE_SECS_ENV => Some("0".to_string()),
            MERGE_CACHE_TTL_SECS_ENV => Some("0".to_string()),
            MERGE_CACHE_MAX_BYTES_ENV => Some("junk".to_string()),
            _ => None,
        };
        let cfg = GateConfig::from_lookup(set, budget, l);
        assert_eq!(cfg.max_merges, 7);
        assert_eq!(
            cfg.queue_wait,
            Duration::from_secs(60),
            "zero deadline is ignored"
        );
        assert_eq!(cfg.cache_ttl, Duration::ZERO, "zero TTL disables the cache");
        assert_eq!(cfg.cache_max_bytes, 1 << 30);
        assert_eq!(cfg.retry_after_secs(), 5);
    }

    #[test]
    fn key_parts_are_length_prefixed() {
        let mut a = MergeKeyBuilder::new(MergeKind::Repodata);
        a.part(b"ab").part(b"c");
        let mut b = MergeKeyBuilder::new(MergeKind::Repodata);
        b.part(b"a").part(b"bc");
        let mut c = MergeKeyBuilder::new(MergeKind::Channeldata);
        c.part(b"ab").part(b"c");
        let (a, b, c) = (a.finish(), b.finish(), c.finish());
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    fn leaked_budget(bytes: usize) -> &'static ProxyMetadataBudget {
        Box::leak(Box::new(ProxyMetadataBudget::new(bytes)))
    }

    #[tokio::test]
    async fn account_reserves_once_tops_up_without_waiting_and_releases() {
        let budget = leaked_budget(1000);
        let mut account =
            MergeAccount::new(MergeKind::Repodata, budget, Duration::from_millis(200), 1);
        account.reserve(600).await.unwrap();
        assert_eq!(budget.available_bytes(), 400);
        // A fetch buffer, decoded into a document: within the reservation.
        account.track(100);
        account.release(100);
        account.track(500);
        assert_eq!(account.reserved(), 600);
        // Outgrowing it tops up from the free budget at once.
        account.track(250);
        assert_eq!(account.reserved(), 750);
        assert_eq!(budget.available_bytes(), 250);
        // With no room left it goes on over its reservation instead of waiting
        // (never hold-and-wait).
        let other = budget.try_reserve(250).unwrap();
        account.track(100);
        assert_eq!(account.reserved(), 750);
        assert_eq!(account.peak_need(), 850);
        drop(other);
        drop(account);
        assert_eq!(budget.available_bytes(), 1000);
    }

    #[tokio::test]
    async fn account_sheds_with_retry_after_when_the_budget_stays_exhausted() {
        let budget = leaked_budget(1000);
        let other = budget.try_reserve(900).unwrap();
        let mut account = MergeAccount::new(
            MergeKind::Channeldata,
            budget,
            Duration::from_millis(100),
            3,
        );
        let started = std::time::Instant::now();
        let err = account.reserve(500).await.unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            err.headers().get(header::RETRY_AFTER).unwrap(),
            HeaderValue::from_static("3")
        );
        drop(other);
        account.reserve(500).await.unwrap();
        // Larger than the whole budget: holds all of it.
        let mut big = MergeAccount::new(MergeKind::Repodata, budget, Duration::from_millis(100), 3);
        drop(account);
        big.reserve(5000).await.unwrap();
        assert_eq!(big.reserved(), 1000);
        assert_eq!(budget.available_bytes(), 0);
    }

    #[test]
    fn learned_estimate_adds_a_margin() {
        assert_eq!(learned_estimate(0), 1024 * 1024);
        assert_eq!(learned_estimate(700_000_000), 770_000_000);
    }

    #[test]
    fn working_set_reservation_covers_the_output() {
        let decoded = 400 * 1024 * 1024;
        assert!(merge_working_set(decoded, true) > decoded * 3 / 2);
        assert!(merge_working_set(decoded, false) >= decoded / 2);
        assert!(merge_working_set(decoded, false) > merge_output_allowance(decoded, false));
        assert_eq!(merge_working_set(0, false), 64 * 1024);
    }
}
