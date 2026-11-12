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
//!    document share one merge, and its result is kept for
//!    `CONDA_VIRTUAL_MERGE_CACHE_TTL_SECS` and served with one ETag per
//!    encoding, so revalidation answers 304. The key is a digest of every input
//!    the merge reads that can change without a member refetch: the virtual,
//!    the document (not its encoding: `repodata.json`, `.zst` and `.bz2` of
//!    one subdir are one merge, see 4), the caller-visible member set, the hosted
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
//! 4. **One merge, several renderings (#4879).** A merged `repodata.json` is
//!    built and kept in one canonical encoding, zstd (the smallest to hold, and
//!    what current clients fetch). The other encodings a client asks for
//!    (plain `.json`, `.bz2`, and the gzip transfer coding of `.json`) are
//!    derived from it on first demand, on a blocking thread, and kept on the
//!    document for as long as it is kept ([`MergeGate::rendering`]). A
//!    rendering is accounted like a merge: it takes a merge slot and reserves
//!    its output plus the encoder's state from the budget before it starts
//!    (the same queue deadline, the same 503), and it holds nothing else while
//!    it waits. Once built it is part of the kept document, and the cache entry
//!    is re-weighed, so `CONDA_VIRTUAL_MERGE_CACHE_MAX_BYTES` bounds every
//!    rendering held, not only the canonical body.
//! 5. **Stale while revalidate (#4879).** A kept document that is no longer
//!    fresh (a member validator changed or expired, or the document outlived
//!    the cache TTL) is still served, for at most
//!    `CONDA_VIRTUAL_MERGE_MAX_STALE_SECS` after it was first found stale,
//!    while ONE background merge (the singleflight entry for its key) rebuilds
//!    it. The rebuilt document replaces it in the cache once it is complete,
//!    including the renderings its predecessor had been asked for, so the
//!    next request gets the new document without waiting on an encoder. Only
//!    a cacheable document (no member failed) is ever kept, so a degraded
//!    merge is never served stale; a rebuild that fails leaves the previous
//!    document in place until its stale bound runs out, and the request after
//!    that waits on a merge as before. `0` turns stale serving off.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures::future::{BoxFuture, FutureExt, Shared};
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::virtual_merge::{MemberFailure, MemberLimits};
use super::RepodataEncoding;
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
/// How long after a kept document was first found stale it may still be
/// served while one background merge rebuilds it (#4879). Defaults to the
/// cache TTL; `0` turns stale serving off (a stale document is dropped and
/// the request waits on the rebuild).
pub(super) const MERGE_MAX_STALE_SECS_ENV: &str = "CONDA_VIRTUAL_MERGE_MAX_STALE_SECS";

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
/// Budget reserved for an encoder's own state on top of a rendering's output
/// (bzip2 at the default level holds about 8 MiB, zstd and gzip less).
const ENCODER_STATE_BYTES: usize = 16 * 1024 * 1024;
/// Longest the cache keeps a document (fresh plus stale), well inside what
/// the cache accepts as a time to live.
const MAX_KEEP: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);

/// What a merge builds; the `kind` label on the merge metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MergeKind {
    Repodata,
    Channeldata,
    ShardIndex,
    /// `run_exports.json` (#4708).
    RunExports,
    /// `current_repodata.json`, derived from a merged `repodata.json` (#4708).
    CurrentRepodata,
    /// Another encoding of a kept merge (`.json`, `.bz2`, gzip), derived
    /// from it on first demand (#4879). Not a merge: only the slot, budget
    /// and shed metrics carry this label.
    Rendering,
}

impl MergeKind {
    /// Whether a stale kept document of this kind may be served while it is
    /// rebuilt (#4879). Not `current_repodata`, which is derived from a
    /// merged `repodata.json` and keyed by its ETag, so it follows whatever
    /// that merge serves; and not the shard index, whose shard routing must
    /// not point at shards an upstream may have dropped.
    fn serves_stale(self) -> bool {
        matches!(self, Self::Repodata | Self::Channeldata | Self::RunExports)
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Repodata => "repodata",
            Self::Channeldata => "channeldata",
            Self::ShardIndex => "shard_index",
            Self::RunExports => "run_exports",
            Self::CurrentRepodata => "current_repodata",
            Self::Rendering => "rendering",
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
    /// How long after it was first found stale a kept document may still be
    /// served while it is rebuilt; zero disables stale serving (#4879).
    pub max_stale: Duration,
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
        let cache_ttl_secs = num(MERGE_CACHE_TTL_SECS_ENV).unwrap_or(DEFAULT_CACHE_TTL_SECS);
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
            cache_ttl: Duration::from_secs(cache_ttl_secs),
            cache_max_bytes: num(MERGE_CACHE_MAX_BYTES_ENV).unwrap_or(DEFAULT_CACHE_MAX_BYTES),
            max_stale: Duration::from_secs(num(MERGE_MAX_STALE_SECS_ENV).unwrap_or(cache_ttl_secs)),
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
    /// The merged document as kept (for `repodata.json`, its canonical zstd
    /// encoding).
    pub output_bytes: usize,
    /// Budget bytes the merge held (its reservation, after any top-up).
    pub reserved: usize,
    /// The most the merge held at once by its own tracking.
    pub peak_need: usize,
}

/// The encodings of a merged `repodata.json` other than its canonical zstd
/// body, each derived from that body on first demand and then kept (#4879).
pub(super) struct Renderings {
    /// Length of the plain JSON document the body decodes to.
    plain_len: usize,
    json: tokio::sync::OnceCell<Bytes>,
    bz2: tokio::sync::OnceCell<Bytes>,
}

impl Renderings {
    fn cell(&self, encoding: RepodataEncoding) -> Option<&tokio::sync::OnceCell<Bytes>> {
        match encoding {
            RepodataEncoding::Json => Some(&self.json),
            RepodataEncoding::Bz2 => Some(&self.bz2),
            RepodataEncoding::Zst => None,
        }
    }
}

/// The encoding a merged `repodata.json` is built and kept in.
pub(super) const CANONICAL_ENCODING: RepodataEncoding = RepodataEncoding::Zst;

/// A finished merge, shared by every request it answers.
pub(super) struct MergedDocument {
    /// The document as kept: plain JSON, CEP-16 msgpack, or for a merged
    /// `repodata.json` its canonical zstd encoding ([`Renderings`]).
    pub body: Bytes,
    /// The ETag of `body`; another encoding of it has its own
    /// ([`Self::etag_for`]).
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
    /// The gzip rendering of the document's plain JSON (the body, or the
    /// `.json` rendering of a merged `repodata.json`), built once on first
    /// demand.
    pub gzip: tokio::sync::OnceCell<Bytes>,
    /// For a merged `repodata.json`: its other encodings (#4879).
    renderings: Option<Renderings>,
    /// For a shard index merge: where every listed shard comes from, so a
    /// shard request is routed from the kept merge (#4607).
    pub shard_index: Option<super::VirtualShardIndex>,
    /// When the merge finished; the document is fresh for the cache TTL
    /// from here (and while its validators hold).
    built_at: Instant,
    /// When the document was first found stale (#4879).
    stale_since: OnceLock<Instant>,
    /// The cache key it is kept under, once kept.
    cache_key: OnceLock<String>,
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
            renderings: None,
            shard_index: None,
            built_at: Instant::now(),
            stale_since: OnceLock::new(),
            cache_key: OnceLock::new(),
        }
    }

    /// Mark the body as the canonical zstd encoding of a merged
    /// `repodata.json` whose plain JSON is `plain_len` bytes, so its other
    /// encodings are derived from it (#4879).
    pub(super) fn with_renderings(mut self, plain_len: usize) -> Self {
        self.renderings = Some(Renderings {
            plain_len,
            json: tokio::sync::OnceCell::new(),
            bz2: tokio::sync::OnceCell::new(),
        });
        self
    }

    /// Whether the document has encodings derived from its body.
    pub(super) fn has_renderings(&self) -> bool {
        self.renderings.is_some()
    }

    /// Length of the document as plain JSON: the body's own, or what a kept
    /// zstd body decodes to.
    pub(super) fn output_plain_len(&self) -> usize {
        self.renderings
            .as_ref()
            .map_or(self.body.len(), |r| r.plain_len)
    }

    /// The ETag of the document in `encoding`: the body's own for the
    /// canonical encoding (or a document without renderings), else the body's
    /// tagged with the encoding. Every encoding is a deterministic function of
    /// the body, so the tag identifies its bytes without building them, and a
    /// revalidation of any encoding can answer 304 without encoding.
    pub(super) fn etag_for(&self, encoding: Option<RepodataEncoding>) -> String {
        match (encoding, &self.renderings) {
            (Some(encoding), Some(_)) if encoding != CANONICAL_ENCODING => {
                let bare = self.etag.trim_end_matches('"');
                let suffix = match encoding {
                    RepodataEncoding::Json => "json",
                    RepodataEncoding::Bz2 => "bz2",
                    RepodataEncoding::Zst => "zst",
                };
                format!("{bare}-{suffix}\"")
            }
            _ => self.etag.clone(),
        }
    }

    /// Whether the document was found stale and is being served while it is
    /// rebuilt (#4879).
    pub(super) fn is_stale(&self) -> bool {
        self.stale_since.get().is_some()
    }

    /// The rendering of a merged `repodata.json` in `encoding`, when it has
    /// been built already (tests).
    #[cfg(test)]
    pub(super) fn rendered(&self, encoding: RepodataEncoding) -> Option<Bytes> {
        self.renderings.as_ref()?.cell(encoding)?.get().cloned()
    }

    /// Attach the shard routing of a shard index merge.
    pub(super) fn with_shard_index(mut self, shard_index: super::VirtualShardIndex) -> Self {
        self.shard_index = Some(shard_index);
        self
    }

    /// Cache weight in bytes: the body plus every rendering built so far. A
    /// rendering built after the document was kept re-weighs its cache entry
    /// ([`MergeGate::reweigh`]), so the weight is what the document holds.
    fn weight(&self) -> u32 {
        let len = |cell: &tokio::sync::OnceCell<Bytes>| cell.get().map_or(0, Bytes::len);
        let mut bytes = self.body.len().saturating_add(len(&self.gzip));
        if let Some(r) = &self.renderings {
            bytes = bytes
                .saturating_add(len(&r.json))
                .saturating_add(len(&r.bz2));
        }
        u32::try_from(bytes).unwrap_or(u32::MAX)
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
        // STREAMING-EXEMPT: replays one merge's own error response (a 502/503/404 line of text, capped at 1 MiB) to every request that shared the merge; never an artifact or metadata body (#4608)
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
    renders_started: AtomicU64,
}

impl MergeGate {
    pub(super) fn new(config: GateConfig, budget: &'static ProxyMetadataBudget) -> Arc<Self> {
        // A kept document is fresh for the TTL and may then be served stale
        // for up to `max_stale` more; [`Self::get_or_merge`] enforces both
        // from the document's own clock, the cache only evicts after both.
        let cache = (!config.cache_ttl.is_zero() && config.cache_max_bytes > 0).then(|| {
            moka::future::Cache::builder()
                .max_capacity(config.cache_max_bytes)
                .weigher(|_key: &String, doc: &Arc<MergedDocument>| doc.weight())
                .time_to_live(
                    config
                        .cache_ttl
                        .saturating_add(config.max_stale)
                        .min(MAX_KEEP),
                )
                .build()
        });
        tracing::info!(
            max_merges = config.max_merges,
            queue_secs = config.queue_wait.as_secs(),
            cache_ttl_secs = config.cache_ttl.as_secs(),
            cache_max_bytes = config.cache_max_bytes,
            max_stale_secs = config.max_stale.as_secs(),
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
            renders_started: AtomicU64::new(0),
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

    /// Renderings this gate has started (tests).
    #[cfg(test)]
    pub(super) fn renders_started(&self) -> u64 {
        self.renders_started.load(Ordering::Acquire)
    }

    /// Keep `doc` under `key` as a finished merge would (tests).
    #[cfg(test)]
    pub(super) async fn keep_for_test(&self, key: &str, doc: Arc<MergedDocument>) {
        let _ = doc.cache_key.set(key.to_string());
        self.cache
            .as_ref()
            .expect("the test gate keeps documents")
            .insert(key.to_string(), doc)
            .await;
    }

    /// Take every merge slot (tests): further merges queue.
    #[cfg(test)]
    pub(super) async fn hold_all_slots(&self) -> OwnedSemaphorePermit {
        Arc::clone(&self.slots)
            .acquire_many_owned(u32::try_from(self.config.max_merges).unwrap())
            .await
            .unwrap()
    }

    /// Serve the merged document `key` from the cache when it is fresh and
    /// `validate` accepts it, else serve it stale while one background merge
    /// rebuilds it (within `max_stale`, for a kind that allows it), else join
    /// the merge already running for `key`, else run `merge`.
    ///
    /// `budget_shape` names the document for budget accounting (the same
    /// document across generations, e.g. virtual + subdir + document name): a
    /// merge with one reserves from the buffered-metadata budget before it
    /// starts, sized from the previous merge of that shape. `None` for a merge
    /// whose fetches reserve their own budget (the shard index).
    ///
    /// The merge runs as its own task, so a client that disconnects does not
    /// cancel the work the other requests are waiting on, and a stale serve
    /// does not wait for it at all.
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
                let now = Instant::now();
                // A TTL past what `Instant` can represent never expires.
                let expires = hit
                    .built_at
                    .checked_add(self.config.cache_ttl)
                    .unwrap_or(now + Duration::from_secs(1));
                if now < expires && !hit.is_stale() && validate(Arc::clone(&hit)).await {
                    metrics_service::record_conda_virtual_merge_cache_hit(kind.label(), "cache");
                    return Ok(hit);
                }
                // Stale: since its TTL ran out, or since now if a validator
                // failed first. Recorded once, so the bound runs from the
                // first request that found it stale.
                let since = *hit.stale_since.get_or_init(|| now.min(expires));
                if kind.serves_stale()
                    && hit.cacheable
                    && !self.config.max_stale.is_zero()
                    && now.saturating_duration_since(since) <= self.config.max_stale
                {
                    let (_, leader) =
                        self.join_or_lead(kind, key, budget_shape, merge, Some(Arc::clone(&hit)));
                    if leader {
                        metrics_service::record_conda_virtual_merge_cache_miss(kind.label());
                    }
                    metrics_service::record_conda_virtual_merge_cache_hit(kind.label(), "stale");
                    return Ok(hit);
                }
                self.forget(&key, &hit).await;
            }
        }

        let (merge_future, leader) = self.join_or_lead(kind, key, budget_shape, merge, None);
        if leader {
            metrics_service::record_conda_virtual_merge_cache_miss(kind.label());
        } else {
            metrics_service::record_conda_virtual_merge_cache_hit(kind.label(), "singleflight");
        }
        merge_future.await
    }

    /// The merge running for `key`, or a new one started from `merge`, and
    /// whether this call started it. `predecessor` is the stale document a
    /// background rebuild replaces.
    fn join_or_lead<M, MF>(
        self: &Arc<Self>,
        kind: MergeKind,
        key: String,
        budget_shape: Option<String>,
        merge: M,
        predecessor: Option<Arc<MergedDocument>>,
    ) -> (InflightMerge, bool)
    where
        M: FnOnce(MergeAccount) -> MF + Send + 'static,
        MF: Future<Output = Result<MergedDocument, Response>> + Send + 'static,
    {
        let mut inflight = self.inflight.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(running) = inflight.get(&key) {
            return (running.clone(), false);
        }
        let gate = Arc::clone(self);
        let task_key = key.clone();
        let lead = async move {
            gate.lead(kind, task_key, budget_shape, merge, predecessor)
                .await
        };
        // A test scopes the virtual member deadline to the request it drives
        // (#5621); the merge runs on its own task, so carry the scope along.
        #[cfg(test)]
        let lead = crate::api::handlers::proxy_helpers::with_virtual_member_deadline(
            crate::api::handlers::proxy_helpers::virtual_member_metadata_timeout(),
            lead,
        );
        let task = tokio::spawn(lead);
        let shared = async move {
            task.await
                .unwrap_or_else(|e| Err(SharedResponse::internal(e)))
        }
        .boxed()
        .shared();
        inflight.insert(key, shared.clone());
        (shared, true)
    }

    /// Drop the kept `doc` from `key`, unless a newer document replaced it
    /// meanwhile.
    async fn forget(&self, key: &str, doc: &Arc<MergedDocument>) {
        use moka::ops::compute::Op;
        let Some(cache) = &self.cache else {
            return;
        };
        let doc = Arc::clone(doc);
        cache
            .entry(key.to_string())
            .and_compute_with(|entry| async move {
                match entry {
                    Some(e) if Arc::ptr_eq(e.value(), &doc) => Op::Remove,
                    _ => Op::Nop,
                }
            })
            .await;
    }

    /// Re-insert a kept document whose renderings grew, so the cache weighs
    /// what it now holds. A document no longer kept (replaced, evicted) is
    /// left alone.
    async fn reweigh(&self, doc: &Arc<MergedDocument>) {
        use moka::ops::compute::Op;
        let (Some(cache), Some(key)) = (&self.cache, doc.cache_key.get()) else {
            return;
        };
        let doc = Arc::clone(doc);
        cache
            .entry(key.clone())
            .and_compute_with(|entry| async move {
                match entry {
                    Some(e) if Arc::ptr_eq(e.value(), &doc) => Op::Put(doc),
                    _ => Op::Nop,
                }
            })
            .await;
    }

    async fn lead<M, MF>(
        self: Arc<Self>,
        kind: MergeKind,
        key: String,
        budget_shape: Option<String>,
        merge: M,
        predecessor: Option<Arc<MergedDocument>>,
    ) -> MergeOutcome
    where
        M: FnOnce(MergeAccount) -> MF,
        MF: Future<Output = Result<MergedDocument, Response>>,
    {
        let outcome = self.run(kind, budget_shape, merge).await;
        if let (Ok(doc), Some(cache)) = (&outcome, &self.cache) {
            if doc.cacheable {
                // A background rebuild replaces a document that is being
                // served stale: build the renderings it had been asked for
                // first, so the switch never makes a client wait on an
                // encoder (#4879).
                if let Some(previous) = &predecessor {
                    self.prerender(kind, previous, doc).await;
                }
                let _ = doc.cache_key.set(key.clone());
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
        let slot = match self.slot(kind).await {
            Ok(slot) => slot,
            Err(shed) => return Err(SharedResponse::from_response(shed).await),
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

    /// A merge slot, waiting at most the queue deadline, else the 503.
    async fn slot(&self, kind: MergeKind) -> Result<OwnedSemaphorePermit, Response> {
        match tokio::time::timeout(
            self.config.queue_wait,
            Arc::clone(&self.slots).acquire_owned(),
        )
        .await
        {
            Ok(Ok(slot)) => Ok(slot),
            _ => {
                metrics_service::record_conda_virtual_merge_rejected(kind.label(), "queue");
                tracing::warn!(
                    kind = kind.label(),
                    max_merges = self.config.max_merges,
                    "conda virtual merge shed: no merge slot within the queue deadline"
                );
                Err(shed_response(
                    self.config.retry_after_secs(),
                    format!(
                        "Too many virtual conda channel merges are running (limit {}, \
                         {MAX_CONCURRENT_MERGES_ENV}); this one waited {} s \
                         ({MERGE_QUEUE_SECS_ENV})",
                        self.config.max_merges,
                        self.config.queue_wait.as_secs()
                    ),
                ))
            }
        }
    }

    /// Run `encode` as a rendering of `doc`: under a merge slot, with
    /// `estimate` bytes reserved from the budget, on a blocking thread
    /// (#4879). The reservation covers the rendering's output and the
    /// encoder's state; the rendering holds no other budget while it waits,
    /// and tops up without waiting if its output outgrows the estimate.
    async fn render_with<F>(
        &self,
        kind: MergeKind,
        estimate: usize,
        encode: F,
    ) -> Result<Bytes, Response>
    where
        F: FnOnce() -> Result<Vec<u8>, Response> + Send + 'static,
    {
        let slot = self.slot(kind).await?;
        let mut account = MergeAccount::new(
            kind,
            self.budget,
            self.config.queue_wait,
            self.config.retry_after_secs(),
        );
        account.reserve(estimate).await?;
        self.renders_started.fetch_add(1, Ordering::AcqRel);
        let out = tokio::task::spawn_blocking(encode)
            .await
            .map_err(super::virtual_merge::internal_error)??;
        account.track(out.len().saturating_add(ENCODER_STATE_BYTES));
        drop(slot);
        Ok(Bytes::from(out))
    }

    /// `doc` (a merged `repodata.json`) in `encoding`: the kept body for the
    /// canonical encoding, else the rendering derived from it, built on first
    /// demand and kept on the document (#4879). Concurrent requests for one
    /// rendering share one build.
    pub(super) async fn rendering(
        &self,
        doc: &Arc<MergedDocument>,
        encoding: RepodataEncoding,
    ) -> Result<Bytes, Response> {
        let Some(cell) = doc.renderings.as_ref().and_then(|r| r.cell(encoding)) else {
            return Ok(doc.body.clone());
        };
        let plain_len = doc.renderings.as_ref().map_or(0, |r| r.plain_len);
        let mut built = false;
        let bytes = cell
            .get_or_try_init(|| {
                built = true;
                let body = doc.body.clone();
                // Plain JSON is the document itself; a compressed encoding is
                // allowed a quarter of it, as a compressed merge output is.
                let output = match encoding {
                    RepodataEncoding::Json => plain_len,
                    _ => merge_output_allowance(plain_len, false),
                };
                self.render_with(
                    MergeKind::Rendering,
                    output.saturating_add(ENCODER_STATE_BYTES),
                    move || encoding.transcode_zst(&body),
                )
            })
            .await?
            .clone();
        if built {
            self.reweigh(doc).await;
        }
        Ok(bytes)
    }

    /// The gzip transfer coding of `json` (the plain JSON of `doc`), built
    /// on first demand and kept on the document; `None` when it cannot be
    /// built (the caller serves `json` uncoded).
    pub(super) async fn gzip_rendering(
        &self,
        doc: &Arc<MergedDocument>,
        json: Bytes,
    ) -> Option<Bytes> {
        let mut built = false;
        let gzip = doc
            .gzip
            .get_or_try_init(|| {
                built = true;
                let estimate = merge_output_allowance(json.len(), false);
                self.render_with(
                    MergeKind::Rendering,
                    estimate.saturating_add(ENCODER_STATE_BYTES),
                    move || Ok(super::gzip_compress(&json)),
                )
            })
            .await
            .map_err(|e| {
                tracing::warn!(
                    status = e.status().as_u16(),
                    "conda gzip rendering failed; serving the body uncoded"
                );
            })
            .ok()
            .cloned();
        if built && gzip.is_some() {
            self.reweigh(doc).await;
        }
        gzip
    }

    /// Build on `doc` the renderings `previous` had been asked for, so `doc`
    /// replaces it without making the next request wait on an encoder. A
    /// rendering that cannot be built is left for that request to build.
    async fn prerender(
        &self,
        kind: MergeKind,
        previous: &Arc<MergedDocument>,
        doc: &Arc<MergedDocument>,
    ) {
        if let (Some(old), Some(_)) = (&previous.renderings, &doc.renderings) {
            for encoding in [RepodataEncoding::Json, RepodataEncoding::Bz2] {
                if old.cell(encoding).is_some_and(|c| c.initialized()) {
                    if let Err(e) = self.rendering(doc, encoding).await {
                        tracing::warn!(
                            kind = kind.label(),
                            encoding = encoding.upstream_filename(),
                            status = e.status().as_u16(),
                            "could not pre-build a rendering of a rebuilt conda merge"
                        );
                    }
                }
            }
        }
        if previous.gzip.initialized() {
            let json = if doc.renderings.is_some() {
                self.rendering(doc, RepodataEncoding::Json).await.ok()
            } else {
                doc.json.then(|| doc.body.clone())
            };
            if let Some(json) = json {
                let _ = self.gzip_rendering(doc, json).await;
            }
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

    /// #4881: the merge cap follows a budget past 4 GiB. The budget used to be
    /// clamped to `u32::MAX` bytes, so 32 GiB configured gave 3 merges.
    #[test]
    fn default_merge_cap_grows_with_a_budget_past_four_gib_4881() {
        const GIB: usize = 1024 * 1024 * 1024;
        let budget = ProxyMetadataBudget::new(32 * GIB);
        assert_eq!(budget.total_bytes(), 34_359_738_368);
        let cfg = GateConfig::from_lookup(|_| None, budget.total_bytes(), limits(128 << 20, GIB));
        // 32 GiB / (128 MiB + 1 GiB) = 28.
        assert_eq!(cfg.max_merges, 28);
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
        assert_eq!(cfg.max_stale, cfg.cache_ttl, "stale for one TTL by default");

        let set = |k: &str| match k {
            MAX_CONCURRENT_MERGES_ENV => Some("7".to_string()),
            MERGE_QUEUE_SECS_ENV => Some("0".to_string()),
            MERGE_CACHE_TTL_SECS_ENV => Some("0".to_string()),
            MERGE_CACHE_MAX_BYTES_ENV => Some("junk".to_string()),
            MERGE_MAX_STALE_SECS_ENV => Some("0".to_string()),
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
        assert_eq!(
            cfg.max_stale,
            Duration::ZERO,
            "zero turns stale serving off"
        );
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
        // Whole budget units, so the byte arithmetic below is exact (#4881).
        const U: usize = proxy_helpers::PROXY_METADATA_BUDGET_UNIT_BYTES;
        let budget = leaked_budget(1000 * U);
        let mut account =
            MergeAccount::new(MergeKind::Repodata, budget, Duration::from_millis(200), 1);
        account.reserve(600 * U).await.unwrap();
        assert_eq!(budget.available_bytes(), 400 * U);
        // A fetch buffer, decoded into a document: within the reservation.
        account.track(100 * U);
        account.release(100 * U);
        account.track(500 * U);
        assert_eq!(account.reserved(), 600 * U);
        // Outgrowing it tops up from the free budget at once.
        account.track(250 * U);
        assert_eq!(account.reserved(), 750 * U);
        assert_eq!(budget.available_bytes(), 250 * U);
        // With no room left it goes on over its reservation instead of waiting
        // (never hold-and-wait).
        let other = budget.try_reserve(250 * U).unwrap();
        account.track(100 * U);
        assert_eq!(account.reserved(), 750 * U);
        assert_eq!(account.peak_need(), 850 * U);
        drop(other);
        drop(account);
        assert_eq!(budget.available_bytes(), 1000 * U);
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

    // -------------------------------------------------------------------
    // #4879: one merge per document, renderings, stale while revalidate
    // -------------------------------------------------------------------

    const KEY: &str = "virtual/linux-64/repodata.json";

    fn new_gate(max_stale_secs: u64) -> Arc<MergeGate> {
        MergeGate::new(
            GateConfig {
                max_merges: 4,
                queue_wait: Duration::from_secs(5),
                cache_ttl: Duration::from_secs(300),
                cache_max_bytes: 64 * 1024 * 1024,
                max_stale: Duration::from_secs(max_stale_secs),
            },
            leaked_budget(256 * 1024 * 1024),
        )
    }

    fn plain(generation: u32) -> Vec<u8> {
        let packages: serde_json::Map<String, serde_json::Value> = (0..200)
            .map(|i| {
                (
                    format!("pkg{i}-{generation}.0-0.conda"),
                    serde_json::json!({"name": format!("pkg{i}"), "version": format!("{generation}.0")}),
                )
            })
            .collect();
        serde_json::to_vec(&serde_json::json!({
            "info": {"subdir": "linux-64"},
            "packages": {},
            "packages.conda": packages,
        }))
        .unwrap()
    }

    /// A merged `repodata.json` of `generation`, kept zstd-encoded as a
    /// merge keeps it; `failed` marks a member failure.
    fn repodata(generation: u32, failed: bool) -> MergedDocument {
        let json = plain(generation);
        let failures = if failed {
            vec![MemberFailure {
                member: "remote".into(),
                kind: "fetch",
                reason: "upstream down".into(),
            }]
        } else {
            Vec::new()
        };
        MergedDocument::new(
            zstd::encode_all(&json[..], 3).unwrap(),
            failures,
            None,
            Vec::new(),
            true,
            MergeStats::default(),
            false,
        )
        .with_renderings(json.len())
    }

    /// A merge that waits for `release` and then produces `generation`.
    fn held_merge(
        generation: u32,
        release: Arc<tokio::sync::Notify>,
    ) -> impl FnOnce(MergeAccount) -> BoxFuture<'static, Result<MergedDocument, Response>> {
        move |_account| {
            async move {
                release.notified().await;
                Ok(repodata(generation, false))
            }
            .boxed()
        }
    }

    fn ready_merge(
        generation: u32,
        failed: bool,
    ) -> impl FnOnce(MergeAccount) -> BoxFuture<'static, Result<MergedDocument, Response>> {
        move |_account| async move { Ok(repodata(generation, failed)) }.boxed()
    }

    async fn get(
        gate: &Arc<MergeGate>,
        fresh: bool,
        merge: impl FnOnce(MergeAccount) -> BoxFuture<'static, Result<MergedDocument, Response>>
            + Send
            + 'static,
    ) -> Arc<MergedDocument> {
        gate.get_or_merge(
            MergeKind::Repodata,
            KEY.to_string(),
            Some(KEY.to_string()),
            move |_| async move { fresh },
            merge,
        )
        .await
        .unwrap_or_else(|_| panic!("merge failed"))
    }

    fn decode(doc: &MergedDocument) -> Vec<u8> {
        zstd::decode_all(&doc.body[..]).unwrap()
    }

    /// `.json`, `.zst` and `.bz2` of one subdir are one merge: the merged
    /// document is kept once and every encoding is derived from it, once,
    /// with its own ETag, and the cache weighs every rendering it holds.
    #[tokio::test]
    async fn every_encoding_is_served_from_one_merge_4879() {
        let gate = new_gate(300);
        let doc = get(&gate, true, ready_merge(1, false)).await;
        let weight_bare = doc.weight();

        let zst = gate.rendering(&doc, RepodataEncoding::Zst).await.unwrap();
        let json = gate.rendering(&doc, RepodataEncoding::Json).await.unwrap();
        let bz2 = gate.rendering(&doc, RepodataEncoding::Bz2).await.unwrap();
        // Asked again, from a request that found the kept document.
        let again = get(&gate, true, ready_merge(99, false)).await;
        let bz2_again = gate.rendering(&again, RepodataEncoding::Bz2).await.unwrap();

        assert_eq!(gate.merges_started(), 1, "one merge for every encoding");
        assert_eq!(gate.renders_started(), 2, ".json and .bz2, each once");
        assert!(Arc::ptr_eq(&doc, &again));
        assert_eq!(zst, doc.body, ".zst is the kept body");
        assert_eq!(&json[..], &plain(1)[..], ".json is the merged document");
        let mut from_bz2 = Vec::new();
        std::io::Read::read_to_end(&mut bzip2::read::BzDecoder::new(&bz2[..]), &mut from_bz2)
            .unwrap();
        assert_eq!(from_bz2, plain(1), ".bz2 holds the same document");
        assert_eq!(bz2_again, bz2);
        let tags = [
            doc.etag_for(Some(RepodataEncoding::Zst)),
            doc.etag_for(Some(RepodataEncoding::Json)),
            doc.etag_for(Some(RepodataEncoding::Bz2)),
        ];
        assert_eq!(tags[0], doc.etag);
        assert!(tags[1] != tags[0] && tags[2] != tags[0] && tags[1] != tags[2]);
        assert!(tags.iter().all(|t| t.starts_with('"') && t.ends_with('"')));
        assert_eq!(
            doc.weight() as usize,
            weight_bare as usize + json.len() + bz2.len(),
            "the kept document weighs its renderings"
        );
    }

    /// A kept document that went stale is served at once while ONE
    /// background merge rebuilds it; the request after the rebuild lands
    /// gets the new document, with the renderings the old one had.
    #[tokio::test]
    async fn stale_document_is_served_while_one_rebuild_runs_4879() {
        let gate = new_gate(300);
        let first = get(&gate, true, ready_merge(1, false)).await;
        gate.rendering(&first, RepodataEncoding::Bz2).await.unwrap();

        let release = Arc::new(tokio::sync::Notify::new());
        let mut served = Vec::new();
        for _ in 0..3 {
            let doc = tokio::time::timeout(
                Duration::from_secs(2),
                get(&gate, false, held_merge(2, Arc::clone(&release))),
            )
            .await
            .expect("a stale document is served without waiting on the rebuild");
            served.push(doc);
        }
        // The rebuild starts in its own task.
        let deadline = Instant::now() + Duration::from_secs(5);
        while gate.merges_started() < 2 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(gate.merges_started(), 2, "three stale serves, one rebuild");
        assert!(served.iter().all(|d| Arc::ptr_eq(d, &first)));
        assert!(
            first.is_stale(),
            "the stale document says so (Warning: 110)"
        );

        release.notify_one();
        let deadline = Instant::now() + Duration::from_secs(10);
        let fresh = loop {
            let doc = get(&gate, true, ready_merge(99, false)).await;
            if !Arc::ptr_eq(&doc, &first) {
                break doc;
            }
            assert!(Instant::now() < deadline, "the rebuild never landed");
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(
            decode(&fresh),
            plain(2),
            "the next request gets the rebuild"
        );
        assert!(!fresh.is_stale());
        assert_eq!(gate.merges_started(), 2, "no merge beyond the one rebuild");
        assert!(
            fresh.rendered(RepodataEncoding::Bz2).is_some(),
            "the rebuild built the .bz2 its predecessor was asked for"
        );
    }

    /// With `CONDA_VIRTUAL_MERGE_MAX_STALE_SECS=0` a stale document is not
    /// served: the request waits on the rebuild, as before #4879.
    #[tokio::test]
    async fn max_stale_zero_waits_for_the_rebuild_4879() {
        let gate = new_gate(0);
        let first = get(&gate, true, ready_merge(1, false)).await;

        let release = Arc::new(tokio::sync::Notify::new());
        let g = Arc::clone(&gate);
        let held = held_merge(2, Arc::clone(&release));
        let request = tokio::spawn(async move { get(&g, false, held).await });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!request.is_finished(), "the request waits on the rebuild");
        release.notify_one();
        let doc = tokio::time::timeout(Duration::from_secs(10), request)
            .await
            .unwrap()
            .unwrap();
        assert!(!Arc::ptr_eq(&doc, &first));
        assert_eq!(decode(&doc), plain(2));
    }

    /// A document with a failed member is never kept, so it is never served
    /// stale: the next request merges again and waits for it. Even one that
    /// is somehow kept is not served stale.
    #[tokio::test]
    async fn uncacheable_document_is_not_served_stale_4879() {
        let gate = new_gate(300);
        let degraded = get(&gate, true, ready_merge(1, true)).await;
        assert!(!degraded.cacheable);

        let release = Arc::new(tokio::sync::Notify::new());
        let g = Arc::clone(&gate);
        let held = held_merge(2, Arc::clone(&release));
        let request = tokio::spawn(async move { get(&g, false, held).await });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !request.is_finished(),
            "a degraded merge is not served stale"
        );
        release.notify_one();
        let doc = tokio::time::timeout(Duration::from_secs(10), request)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decode(&doc), plain(2));

        // The guard itself: a kept document marked uncacheable.
        let other = new_gate(300);
        let kept = Arc::new(repodata(3, true));
        other.keep_for_test(KEY, Arc::clone(&kept)).await;
        let release = Arc::new(tokio::sync::Notify::new());
        let g = Arc::clone(&other);
        let held = held_merge(4, Arc::clone(&release));
        let request = tokio::spawn(async move { get(&g, false, held).await });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !request.is_finished(),
            "an uncacheable document is never stale-served"
        );
        release.notify_one();
        let doc = tokio::time::timeout(Duration::from_secs(10), request)
            .await
            .unwrap()
            .unwrap();
        assert!(!Arc::ptr_eq(&doc, &kept));
        assert_eq!(decode(&doc), plain(4));
    }

    /// The stale bound runs from when the document was first found stale:
    /// past it, the request waits on the rebuild.
    #[tokio::test]
    async fn stale_serving_is_bounded_by_max_stale_4879() {
        let gate = new_gate(1);
        let first = get(&gate, true, ready_merge(1, false)).await;
        // Found stale; served stale, its rebuild held.
        let release = Arc::new(tokio::sync::Notify::new());
        let stale = get(&gate, false, held_merge(2, Arc::clone(&release))).await;
        assert!(Arc::ptr_eq(&stale, &first));
        tokio::time::sleep(Duration::from_millis(1200)).await;
        // Past the bound: this request joins the running rebuild.
        let g = Arc::clone(&gate);
        let request = tokio::spawn(async move { get(&g, false, ready_merge(99, false)).await });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!request.is_finished(), "past max-stale the request waits");
        release.notify_one();
        let doc = tokio::time::timeout(Duration::from_secs(10), request)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decode(&doc), plain(2));
        assert_eq!(gate.merges_started(), 2, "it joined the one rebuild");
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
