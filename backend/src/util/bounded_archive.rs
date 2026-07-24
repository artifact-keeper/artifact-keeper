//! Bounded archive decompression for ingestion/serve metadata extraction.
//!
//! Every format that needs package coordinates (name/version/description)
//! decompresses the uploaded or served archive *inside the request handler* to
//! read a single small metadata file (`Chart.yaml`, `.nuspec`, `pubspec.yaml`,
//! `METADATA`, `.podspec.json`, `metadata.config`, …). Those extractors never
//! touch the scanner's bounded extractors (`unpack_*_limited`, #2514) nor the
//! Debian-index cap (#2482), so historically they decoded a gzip/zip/bz2 stream
//! with **no cap on total decompressed bytes**, walked tar entries with **no
//! entry-count cap**, and read the target entry with **no per-entry cap** — a
//! decompression-bomb / unbounded-memory surface at upload and serve time.
//!
//! This module consolidates the proven bounding primitives into three shared
//! helpers so every ingestion metadata extractor gets the same three caps with
//! one implementation:
//!
//! 1. a **total decompressed-byte budget** on the decoded stream (default
//!    128 MiB, env [`MAX_INGEST_DECOMPRESSED_BYTES_ENV`]) — the core mechanism;
//!    it defeats both the *pre-target-inflation* bomb (huge entries walked
//!    before the metadata file) and the *entry-count* bomb (the walk hits the
//!    byte budget and stops),
//! 2. a **10 000 entry-count cap** ([`MAX_INGEST_ARCHIVE_ENTRIES`]) —
//!    defence-in-depth against inode/entry-count bombs with a clearer error,
//! 3. an **8 MiB per-metadata-entry cap** ([`MAX_INGEST_METADATA_ENTRY_BYTES`])
//!    — a metadata file larger than this is itself a bomb.
//!
//! Reference implementations reused here (do not re-derive):
//! - the scanner's `positive_env_or` env-override idiom and `copy_entry_bounded`
//!   running-budget check (#2514),
//! - the Debian index `.take()` byte budget (#2482),
//! - `api/handlers/conda.rs::limited_decode_zstd` streaming cap,
//! - **`api/handlers/swift.rs::extract_manifest_from_zip`** — already correctly
//!   bounded (`size()` pre-check + `.take(N + 1)` per entry, random-access zip
//!   so unmatched entries are never inflated); this module generalises exactly
//!   that pattern to the other formats.
//!
//! All caps sit far above real packages — metadata files are KB-scale, so a
//! legitimate large chart/wheel/nupkg/pod/gem reads only a few KB before the
//! match and never approaches a cap. A cap breach is surfaced as
//! [`AppError::Validation`] (HTTP 400) so ingestion **rejects** the bomb rather
//! than silently truncating or hanging.

use std::collections::HashMap;
use std::io::{self, Read, Seek};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::{AppError, Result};

/// Total decompressed bytes any single ingestion metadata-extraction may
/// consume before it is rejected as a suspected decompression bomb. 128 MiB
/// matches the Debian #2482 index cap; it is generous for real charts/wheels/
/// nupkgs (whose metadata files are KB) — the cap only bites on bombs or on
/// pre-target inflation.
pub const DEFAULT_MAX_INGEST_DECOMPRESSED_BYTES: u64 = 128 * 1024 * 1024;

/// Env var overriding [`DEFAULT_MAX_INGEST_DECOMPRESSED_BYTES`]. Value is a
/// plain decimal byte count; blank/zero/non-numeric falls back to the default.
/// Named to mirror the scanner's `MAX_SCAN_EXTRACTED_BYTES` so operators tune
/// ingestion and scan caps with the same idiom.
pub const MAX_INGEST_DECOMPRESSED_BYTES_ENV: &str = "MAX_INGEST_DECOMPRESSED_BYTES";

/// Maximum tar/zip entries walked while searching for the metadata file.
/// 10 000 matches conda's `MAX_TAR_ENTRIES`; bounds inode/entry-count bombs.
pub const MAX_INGEST_ARCHIVE_ENTRIES: u64 = 10_000;

/// Maximum bytes read for the single matched metadata entry (`Chart.yaml` /
/// `.nuspec` / `pubspec.yaml` / `METADATA` / …). 8 MiB is ≥ helm's prior 4 MiB
/// per-entry cap; a metadata file larger than this is itself a bomb.
pub const MAX_INGEST_METADATA_ENTRY_BYTES: u64 = 8 * 1024 * 1024;

/// Parse a positive-integer environment override, falling back to `default`
/// when the variable is unset, blank, non-numeric, or zero (a zero cap would
/// reject every upload, so it is treated as "unset"). Mirrors the scanner's
/// `positive_env_or` so the parse/filter logic reads identically.
pub fn positive_env_or(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(default)
}

/// Effective total decompressed-byte ceiling, honouring
/// [`MAX_INGEST_DECOMPRESSED_BYTES_ENV`] over the default.
pub fn max_ingest_decompressed_bytes() -> u64 {
    positive_env_or(
        MAX_INGEST_DECOMPRESSED_BYTES_ENV,
        DEFAULT_MAX_INGEST_DECOMPRESSED_BYTES,
    )
}

// ---------------------------------------------------------------------------
// Concurrency cap (#2561)
// ---------------------------------------------------------------------------
//
// The three per-archive caps above bound a *single* extraction's memory/CPU,
// but place no bound on the NUMBER of extractions running at once. Every
// ingestion/serve metadata extractor decodes on the request path, so N parallel
// uploads decode N archives concurrently — N × up-to-`max_ingest_decompressed_bytes()`
// decode buffers plus N × decompressor CPU at the same time. This mirrors the
// scanner's own concurrent-extraction gap (`scanner_service.rs` #2540), which
// caps in-flight scan-workspace extractions with a process-wide semaphore.
//
// This module adds the ingestion analogue: a process-wide semaphore whose
// permits bound the number of concurrent ingestion decodes. Unlike the
// scanner's FIFO *blocking* acquire (detached background scans have no client
// latency SLA and must complete), ingestion decode happens on the request path,
// so the guard is acquired FAST-FAIL: on saturation it sheds the request with a
// 503 ([`AppError::ServiceUnavailable`]) instead of queueing more decode work.
// It is a *separate* semaphore from the scanner's, so ingestion and scan
// extractions do not double-count against one shared budget.

/// Default cap on how many ingestion/serve archive decompressions may run at
/// once, across ALL format extractors. Bounds worst-case concurrent decode
/// memory/CPU to roughly `cap × per-archive-cap`. A small default keeps the
/// out-of-the-box worst case modest while still allowing parallel uploads.
pub const DEFAULT_MAX_CONCURRENT_INGEST_EXTRACTIONS: usize = 8;

/// Env var overriding [`DEFAULT_MAX_CONCURRENT_INGEST_EXTRACTIONS`]. A blank,
/// non-numeric, or zero value falls back to the default (a zero cap would wedge
/// every upload, so it is treated as "unset").
pub const MAX_CONCURRENT_INGEST_EXTRACTIONS_ENV: &str = "MAX_CONCURRENT_INGEST_EXTRACTIONS";

/// Clamp a parsed permit count into the range tokio's `Semaphore` accepts.
/// `Semaphore::new` panics above [`Semaphore::MAX_PERMITS`] (2^61 - 1), and a
/// panic inside the `OnceLock` initializer would re-panic on EVERY subsequent
/// decode (the init is retried), wedging all ingestion — so an absurd override
/// is clamped rather than trusted. The floor of 1 keeps the semaphore usable
/// even if a caller ever bypasses `positive_env_or`'s zero filter.
fn clamp_ingest_permits(v: u64) -> usize {
    usize::try_from(v)
        .unwrap_or(usize::MAX)
        .clamp(1, Semaphore::MAX_PERMITS)
}

/// Effective concurrent-ingest-extraction cap, honouring
/// [`MAX_CONCURRENT_INGEST_EXTRACTIONS_ENV`] over the default, clamped to what
/// `Semaphore::new` accepts (see [`clamp_ingest_permits`]).
fn max_concurrent_ingest_extractions() -> usize {
    clamp_ingest_permits(positive_env_or(
        MAX_CONCURRENT_INGEST_EXTRACTIONS_ENV,
        DEFAULT_MAX_CONCURRENT_INGEST_EXTRACTIONS as u64,
    ))
}

/// Process-wide semaphore bounding concurrent ingestion decompressions. Seeded
/// once from [`max_concurrent_ingest_extractions`]; each in-flight extraction
/// holds one permit (via [`IngestExtractionGuard`]) only for the duration of the
/// decode. Never `close()`d — it lives for the process lifetime.
fn ingest_extraction_semaphore() -> &'static Arc<Semaphore> {
    static SEM: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| Arc::new(Semaphore::new(max_concurrent_ingest_extractions())))
}

/// RAII guard representing one in-flight ingestion decompression. Hold it across
/// the (synchronous) decode call and drop it promptly afterwards — dropping it
/// releases the permit(s) so a slow downstream (DB/storage) never keeps a decode
/// slot occupied. Acquire it with [`acquire_ingest_extraction`].
///
/// The guard holds up to two permits: the process-wide global permit (the hard
/// ceiling, #2561) and — when the extraction is attributed to a tenant (#2598) —
/// the tenant's per-tenant sub-limit permit. Both are released together on drop.
#[must_use = "hold the guard across the decode; dropping it immediately releases the permit"]
#[derive(Debug)]
pub struct IngestExtractionGuard {
    /// Global ceiling permit (#2561) — always held.
    _global: OwnedSemaphorePermit,
    /// Per-tenant sub-limit permit (#2598) — held only on the keyed path; the
    /// global-only `_from` seam and background/unattributed callers leave it
    /// `None`.
    _tenant: Option<OwnedSemaphorePermit>,
}

/// Try to reserve one ingestion-decompression slot on `sem`, FAST-FAIL: on
/// saturation return an [`AppError::ServiceUnavailable`] (HTTP 503) rather than
/// blocking, so an overloaded server sheds excess decode work instead of piling
/// up memory/CPU. The `_from` seam takes the semaphore explicitly so tests can
/// drive a local cap without touching the process singleton.
///
/// This is the *global-only* acquire (no per-tenant sub-limit); the keyed
/// fairness path is [`acquire_ingest_extraction_paired`].
fn acquire_ingest_extraction_from(sem: &Arc<Semaphore>) -> Result<IngestExtractionGuard> {
    match sem.clone().try_acquire_owned() {
        Ok(permit) => Ok(IngestExtractionGuard {
            _global: permit,
            _tenant: None,
        }),
        Err(_) => Err(global_ingest_busy_err()),
    }
}

/// The 503 shed when the *global* ingestion ceiling is saturated.
fn global_ingest_busy_err() -> AppError {
    AppError::ServiceUnavailable(
        "Server is busy decompressing other uploads; please retry shortly".to_string(),
    )
}

/// Reserve one process-wide ingestion-decompression slot, FAST-FAIL to a 503 on
/// saturation. Applies the per-tenant fairness sub-limit (#2598) for the
/// ambient tenant (see [`current_tenant`]) *before* the global ceiling, so a
/// single noisy tenant can never consume the whole global budget and starve its
/// neighbours. Call this in the async handler immediately before invoking the
/// (synchronous) archive extractor and hold the returned guard across that call.
/// Most call sites should prefer [`with_ingest_extraction`] /
/// [`with_ingest_extraction_async`], which scope the permit for you.
pub fn acquire_ingest_extraction() -> Result<IngestExtractionGuard> {
    acquire_ingest_extraction_keyed(
        ingest_extraction_semaphore(),
        &current_tenant(),
        max_concurrent_ingest_extractions_per_tenant(),
    )
}

/// Run `decode` (a synchronous archive decompression) while holding one
/// process-wide ingestion-decompression slot. FAST-FAILS with the 503
/// [`AppError::ServiceUnavailable`] on saturation *without* invoking `decode`;
/// otherwise the permit is held exactly for the duration of `decode` and
/// released as it returns (before any DB/storage work in the caller). `decode`'s
/// own return value — `Result`, `Option`, plain value — passes through inside
/// the `Ok`, so callers layer their existing error mapping on top:
///
/// ```ignore
/// let spec = with_ingest_extraction(|| extract_gemspec(&body))
///     .map_err(|e| e.into_response())?   // 503 shed
///     .map_err(|e| bad_request(e))?;     // decode's own error
/// ```
///
/// **This budget is for the *ingest* (publish/upload) path only.** A read path
/// that needs to re-open a stored archive must use
/// [`with_registry_extraction`] instead — see its docs for why.
pub fn with_ingest_extraction<T>(decode: impl FnOnce() -> T) -> Result<T> {
    let _permit = acquire_ingest_extraction()?;
    Ok(decode())
}

/// `_from` seam for [`with_ingest_extraction`] — lets unit tests drive a local
/// (global-only) cap without touching the process singleton or the per-tenant
/// registry.
fn with_ingest_extraction_from<T>(sem: &Arc<Semaphore>, decode: impl FnOnce() -> T) -> Result<T> {
    let _permit = acquire_ingest_extraction_from(sem)?;
    Ok(decode())
}

/// Like [`with_ingest_extraction`] but holds the slot across an `.await` — for
/// decodes that hop to a blocking thread (`spawn_blocking`) so the permit must
/// span the join. Same fast-fail-503 semantics; the future is never constructed
/// when the server is saturated.
pub async fn with_ingest_extraction_async<T, F>(decode: impl FnOnce() -> F) -> Result<T>
where
    F: std::future::Future<Output = T>,
{
    let _permit = acquire_ingest_extraction()?;
    Ok(decode().await)
}

// ---------------------------------------------------------------------------
// Per-tenant fairness sub-limit (#2598)
// ---------------------------------------------------------------------------
//
// The global cap above (#2561) bounds worst-case aggregate decode memory/CPU,
// but it is fair only in aggregate: one noisy tenant firing many concurrent
// uploads can consume every global permit and starve other tenants, which then
// see 503s caused entirely by a neighbour. This layer adds per-tenant fairness
// at the SAME acquire seam so all ~20 extractor call sites inherit it.
//
// Fairness key: the **repository** (`TenantKey::Repo(repo_id)`). A repository is
// AK's natural tenant boundary — it belongs to exactly one organisation and
// every ingestion/serve decode targets exactly one repo. Crucially,
// `repo_visibility_middleware` already resolves the repo id once for every
// format ingestion/serve route, so a single ambient scope set there
// ([`run_with_tenant_scope`]) attributes every downstream extractor decode to
// its tenant with no per-handler plumbing. Contexts with no request-scoped repo
// (background curation sync / migration import, or the middleware branches that
// never resolve a repo) run under [`TenantKey::Unattributed`], a shared bucket
// still bounded by the global ceiling.
//
// Mechanism: each tenant gets its own small semaphore (the sub-limit). An
// acquire takes the tenant sub-permit FIRST (fast-fail 503 when the tenant is
// already at its sub-limit, so it sheds without ever touching a global permit),
// THEN the global permit as the hard backstop (fast-fail 503 when the global
// ceiling is saturated). Shedding both with a 503 mirrors #2561's fast-fail
// semantics rather than queueing more decode work. The sub-limit is clamped to
// at most the global ceiling (a sub-limit above the ceiling can never bind).
//
// The tenant semaphores live in a `Weak`-valued registry: while a tenant holds
// any permit its semaphore is kept alive by the guard's owned permit; once idle
// the `Arc` drops, the `Weak` dies, and the entry self-cleans on the next
// lookup, so the registry cannot grow unboundedly across a churn of tenants.

/// Fairness key identifying a tenant for the per-tenant ingest sub-limit.
///
/// See the module note above: the repository is the tenant boundary. Background
/// or pre-resolve contexts with no request-scoped repo share
/// [`TenantKey::Unattributed`], which is still bounded by the global ceiling.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TenantKey {
    /// A request attributed to a specific repository.
    Repo(uuid::Uuid),
    /// No request-scoped repository (background workers, or middleware branches
    /// that never resolved a repo). One shared bucket, global ceiling only.
    Unattributed,
}

/// Default per-tenant sub-limit: at most this many concurrent ingestion decodes
/// may be attributed to a single tenant. Kept below the global default (8) so
/// one tenant cannot monopolise the global budget; the remainder always stays
/// available to other tenants.
pub const DEFAULT_MAX_CONCURRENT_INGEST_EXTRACTIONS_PER_TENANT: usize = 4;

/// Env var overriding [`DEFAULT_MAX_CONCURRENT_INGEST_EXTRACTIONS_PER_TENANT`].
/// Same blank/non-numeric/zero fallback rules as the global cap; additionally
/// clamped to at most the effective global ceiling (see
/// [`effective_per_tenant_cap`]).
pub const MAX_CONCURRENT_INGEST_EXTRACTIONS_PER_TENANT_ENV: &str =
    "MAX_CONCURRENT_INGEST_EXTRACTIONS_PER_TENANT";

/// Clamp a configured per-tenant sub-limit into `[1, global]`. A sub-limit above
/// the global ceiling can never bind (the global backstop sheds first), so it is
/// pointless and is clamped to the ceiling; the floor of 1 keeps the sub-limit
/// usable. Pure (no env / no singletons) so it is trivially unit-testable.
fn effective_per_tenant_cap(configured: usize, global: usize) -> usize {
    configured.min(global).max(1)
}

/// Effective per-tenant concurrent-ingest sub-limit, honouring
/// [`MAX_CONCURRENT_INGEST_EXTRACTIONS_PER_TENANT_ENV`] over the default and
/// clamped to the global ceiling.
fn max_concurrent_ingest_extractions_per_tenant() -> usize {
    let configured = clamp_ingest_permits(positive_env_or(
        MAX_CONCURRENT_INGEST_EXTRACTIONS_PER_TENANT_ENV,
        DEFAULT_MAX_CONCURRENT_INGEST_EXTRACTIONS_PER_TENANT as u64,
    ));
    effective_per_tenant_cap(configured, max_concurrent_ingest_extractions())
}

tokio::task_local! {
    /// The tenant the current request's ingestion decodes are attributed to.
    /// Set once per request by `repo_visibility_middleware` via
    /// [`run_with_tenant_scope`]; unset outside a request (background workers).
    static INGEST_TENANT: TenantKey;
}

/// The tenant key in ambient scope, or [`TenantKey::Unattributed`] when none is
/// set (background workers, tests, or the pre-resolve middleware branches).
/// A plain synchronous read — safe to call from the non-async acquire seam.
fn current_tenant() -> TenantKey {
    INGEST_TENANT
        .try_with(|k| k.clone())
        .unwrap_or(TenantKey::Unattributed)
}

/// Run `fut` with `key` as the ambient ingest tenant, so every
/// `acquire_ingest_extraction` / `with_ingest_extraction*` call made while `fut`
/// runs is attributed to that tenant's fairness sub-limit. Called by
/// `repo_visibility_middleware` around the downstream handler once the repo is
/// resolved — the single seam that gives every format extractor per-tenant
/// fairness with no per-handler plumbing.
pub async fn run_with_tenant_scope<F>(key: TenantKey, fut: F) -> F::Output
where
    F: std::future::Future,
{
    INGEST_TENANT.scope(key, fut).await
}

/// Process-wide registry of per-tenant sub-semaphores. `Weak` values so an idle
/// tenant's semaphore self-evicts once no permit is held (see the module note).
fn tenant_registry() -> &'static Mutex<HashMap<TenantKey, Weak<Semaphore>>> {
    static REG: OnceLock<Mutex<HashMap<TenantKey, Weak<Semaphore>>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Get (or create) the sub-semaphore for `key`, sized `per_tenant`. While a
/// tenant holds any permit the returned `Arc` (ultimately the guard's owned
/// permit) keeps it alive; once idle the `Weak` dies and the entry is pruned on
/// the next lookup, bounding the registry to the set of *currently active*
/// tenants.
fn tenant_semaphore_for(key: &TenantKey, per_tenant: usize) -> Arc<Semaphore> {
    let mut map = tenant_registry()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    if let Some(existing) = map.get(key).and_then(Weak::upgrade) {
        return existing;
    }
    // Miss or dead entry: prune any other dead entries (cheap self-cleaning),
    // then create and register a fresh sub-semaphore for this tenant.
    map.retain(|_, w| w.strong_count() > 0);
    let sem = Arc::new(Semaphore::new(per_tenant));
    map.insert(key.clone(), Arc::downgrade(&sem));
    sem
}

/// Acquire against an explicit (global, tenant) semaphore pair, FAST-FAIL. Takes
/// the tenant sub-permit first (so a tenant at its sub-limit sheds without
/// touching a global permit), then the global permit as the hard backstop. On a
/// global shed the already-taken tenant permit is dropped on early return, so no
/// permit leaks. The explicit-pair signature is the deterministic unit-test
/// seam (no singletons / no ambient scope).
fn acquire_ingest_extraction_paired(
    global_sem: &Arc<Semaphore>,
    tenant_sem: &Arc<Semaphore>,
) -> Result<IngestExtractionGuard> {
    let tenant_permit = tenant_sem.clone().try_acquire_owned().map_err(|_| {
        AppError::ServiceUnavailable(
            "Too many concurrent uploads for this repository; please retry shortly".to_string(),
        )
    })?;
    let global_permit = global_sem
        .clone()
        .try_acquire_owned()
        .map_err(|_| global_ingest_busy_err())?;
    Ok(IngestExtractionGuard {
        _global: global_permit,
        _tenant: Some(tenant_permit),
    })
}

/// Keyed acquire: resolve the tenant sub-semaphore for `key` from the registry
/// and acquire the (tenant, global) pair. This is the production path
/// [`acquire_ingest_extraction`] uses with the process singleton global.
fn acquire_ingest_extraction_keyed(
    global_sem: &Arc<Semaphore>,
    key: &TenantKey,
    per_tenant: usize,
) -> Result<IngestExtractionGuard> {
    let tenant_sem = tenant_semaphore_for(key, per_tenant);
    acquire_ingest_extraction_paired(global_sem, &tenant_sem)
}

// ---------------------------------------------------------------------------
// Registry/read-path extraction budget
//
// A few read paths must re-open an archive that is already stored, to recover a
// fact about it that was not captured at publish (the hex registry's
// `inner_checksum` for artifacts published before that capture existed). That
// decode needs the same bounding as ingestion, but it must NOT draw on the same
// budget:
//
//   * The ingest semaphore is shared by EVERY format's publish path. Spending
//     its permits on reads lets read traffic shed *publishes* — across formats
//     that have nothing to do with the reader. A handful of concurrent
//     anonymous GETs could 503 every upload in the product.
//   * The two have opposite shapes. Ingest decode is once per upload, bounded
//     by the client's own upload rate. A registry read can fan out to one
//     decode per release *within a single request*, so it saturates a small
//     budget far more easily.
//
// Reads therefore get their own semaphore with the same fast-fail-503
// discipline. Saturating it degrades registry reads only; publishes are
// untouched. This budget is a backstop, not the primary mechanism — callers are
// expected to persist what they recover so the re-read happens at most once per
// artifact rather than once per request.
// ---------------------------------------------------------------------------

/// Default cap on how many registry/read-path archive decompressions may run at
/// once. Separate from (and additive to)
/// [`DEFAULT_MAX_CONCURRENT_INGEST_EXTRACTIONS`].
pub const DEFAULT_MAX_CONCURRENT_REGISTRY_EXTRACTIONS: usize = 4;

/// Env var overriding [`DEFAULT_MAX_CONCURRENT_REGISTRY_EXTRACTIONS`]. Same
/// blank/non-numeric/zero fallback rules as the ingest cap.
pub const MAX_CONCURRENT_REGISTRY_EXTRACTIONS_ENV: &str = "MAX_CONCURRENT_REGISTRY_EXTRACTIONS";

/// Effective concurrent-registry-extraction cap.
fn max_concurrent_registry_extractions() -> usize {
    clamp_ingest_permits(positive_env_or(
        MAX_CONCURRENT_REGISTRY_EXTRACTIONS_ENV,
        DEFAULT_MAX_CONCURRENT_REGISTRY_EXTRACTIONS as u64,
    ))
}

/// Process-wide semaphore bounding concurrent registry/read-path
/// decompressions. Deliberately a *different* singleton from
/// [`ingest_extraction_semaphore`] so read load can never shed uploads.
fn registry_extraction_semaphore() -> &'static Arc<Semaphore> {
    static SEM: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| Arc::new(Semaphore::new(max_concurrent_registry_extractions())))
}

/// Run `decode` (a synchronous archive decompression on a *read* path) while
/// holding one process-wide registry-decompression slot. Identical
/// fast-fail-503 semantics to [`with_ingest_extraction`], but on its own budget
/// — see the module note above for why the two must not share.
pub fn with_registry_extraction<T>(decode: impl FnOnce() -> T) -> Result<T> {
    with_ingest_extraction_from(registry_extraction_semaphore(), decode)
}

/// Test-only scaffolding for suites that manipulate the process-wide extraction
/// semaphores.
#[cfg(test)]
pub(crate) mod test_support {
    /// Serializes tests that touch the PROCESS-WIDE extraction semaphores,
    /// wherever they live in the crate.
    ///
    /// `cargo test` runs tests as threads in one process, so a test that
    /// deliberately saturates a singleton would otherwise shed a concurrent
    /// test's acquire and make it flake. (Under `cargo nextest`, which CI uses,
    /// each test is its own process and this is moot — but the suite must be
    /// correct under both runners.) The semaphores are process-wide, so the lock
    /// guarding them has to be too: a per-module lock would not serialize a
    /// handler test against a `bounded_archive` test.
    ///
    /// A `tokio::sync::Mutex` rather than a `std` one because async tests hold
    /// the guard across `.await`.
    static SINGLETON_SEM_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Take the lock from a synchronous test.
    pub(crate) fn lock_singletons() -> tokio::sync::MutexGuard<'static, ()> {
        SINGLETON_SEM_LOCK.blocking_lock()
    }

    /// Take the lock from an async test; safe to hold across `.await`.
    pub(crate) async fn lock_singletons_async() -> tokio::sync::MutexGuard<'static, ()> {
        SINGLETON_SEM_LOCK.lock().await
    }
}

/// A `Read` wrapper enforcing a hard cumulative-byte budget on a *decoded*
/// stream. Once `budget` bytes have been read it probes for one more byte: a
/// genuine EOF exactly at the budget passes, but any further data trips an
/// [`io::ErrorKind::InvalidData`] error carrying [`BOMB_SENTINEL`]. This makes a
/// decompression bomb abort *mid-inflate* (the budget is on the stream, not on
/// a buffered result), and — unlike a bare `.take()` — surfaces an explicit
/// error instead of silently truncating the archive.
struct BudgetReader<R> {
    inner: R,
    remaining: u64,
}

/// Marker embedded in the budget-breach `io::Error` so the tar/zip boundary can
/// translate it into a clear "decompression bomb" validation error.
const BOMB_SENTINEL: &str = "ingest decompression budget exceeded";

impl<R: Read> BudgetReader<R> {
    fn new(inner: R, budget: u64) -> Self {
        Self {
            inner,
            remaining: budget,
        }
    }
}

impl<R: Read> Read for BudgetReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            // Budget spent: distinguish a clean EOF from further inflation.
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::new(io::ErrorKind::InvalidData, BOMB_SENTINEL)),
            };
        }
        let cap = std::cmp::min(buf.len() as u64, self.remaining) as usize;
        let n = self.inner.read(&mut buf[..cap])?;
        self.remaining -= n as u64;
        Ok(n)
    }
}

/// Translate a low-level archive `io::Error` into an [`AppError::Validation`],
/// mapping a budget breach to an explicit decompression-bomb message.
fn map_archive_err(context: &str, err: &io::Error) -> AppError {
    if err.to_string().contains(BOMB_SENTINEL) {
        AppError::Validation(
            "Archive expands beyond the decompression budget; refusing suspected decompression bomb"
                .to_string(),
        )
    } else {
        AppError::Validation(format!("{}: {}", context, err))
    }
}

/// Wrap a *decoded* stream in the shared total-byte budget so a decompression
/// bomb aborts mid-inflate. Use when a caller must drive its own tar/zip walk
/// (e.g. to keep a format-specific per-entry cap or message) but still wants the
/// module's total-byte defence; pair it with [`MAX_INGEST_ARCHIVE_ENTRIES`] for
/// the entry-count cap. A budget breach surfaces as an [`io::Error`] during the
/// walk, which the caller maps to its own validation error.
pub fn budgeted<R: Read>(reader: R) -> impl Read {
    budgeted_to(reader, max_ingest_decompressed_bytes())
}

/// Like [`budgeted`] but with an explicit byte budget. Callers that decompress a
/// *whole* stream (not a tar walk) — e.g. an upstream repo index — use this to
/// pick a budget appropriate to the payload, and unit tests use it to drive a
/// tiny budget against a tiny fixture.
pub fn budgeted_to<R: Read>(reader: R, budget: u64) -> impl Read {
    BudgetReader::new(reader, budget)
}

/// Read at most `cap` bytes from `reader`, rejecting input that exceeds `cap`.
///
/// Reads `cap + 1` bytes so an exactly-at-cap breach is detected rather than
/// silently truncated (mirrors swift's `.take(N + 1)` re-check). Used both for
/// the matched metadata entry inside the tar/zip walkers and directly by
/// callers that read a single already-located archive entry (conda zip-entry
/// reads, pypi wheel `METADATA`).
pub fn read_capped<R: Read>(reader: R, cap: u64, what: &str) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader
        .take(cap + 1)
        .read_to_end(&mut buf)
        .map_err(|e| AppError::Validation(format!("Failed to read {}: {}", what, e)))?;
    if buf.len() as u64 > cap {
        return Err(AppError::Validation(format!(
            "{} exceeds the maximum allowed size of {} bytes",
            what, cap
        )));
    }
    Ok(buf)
}

/// Walk an already-budget-wrapped tar stream, returning the first entry whose
/// path satisfies `matches`. Enforces the entry-count cap and reads the matched
/// entry through the per-entry cap. The total-byte budget is enforced by the
/// [`BudgetReader`] the caller wrapped `archive_reader` in, so *skipped* entries
/// (which tar must still inflate to reach the next header) also count against
/// the budget — defeating the pre-target-inflation bomb.
fn read_tar_entries<R: Read>(
    archive_reader: R,
    matches: impl Fn(&Path) -> bool,
    max_entries: u64,
    max_entry: u64,
) -> Result<Option<Vec<u8>>> {
    let mut archive = tar::Archive::new(archive_reader);

    let entries = archive
        .entries()
        .map_err(|e| map_archive_err("Invalid archive", &e))?;

    let mut entries_seen: u64 = 0;
    for entry in entries {
        let mut entry = entry.map_err(|e| map_archive_err("Invalid archive entry", &e))?;

        entries_seen += 1;
        if entries_seen > max_entries {
            return Err(AppError::Validation(format!(
                "Archive contains too many entries (> {}); refusing suspected decompression bomb",
                max_entries
            )));
        }

        let path = entry
            .path()
            .map_err(|e| map_archive_err("Invalid entry path", &e))?
            .to_path_buf();

        if matches(&path) {
            let bytes = read_capped(&mut entry, max_entry, "archive metadata entry")?;
            return Ok(Some(bytes));
        }
    }

    Ok(None)
}

/// Read the first matching metadata entry from a gzip-compressed tar stream,
/// bounded by the total-byte budget, entry-count cap, and per-entry cap.
/// `matches` selects the target entry by its path (e.g. `pubspec.yaml`,
/// `.podspec.json`). Returns `Ok(None)` when no entry matches (not a bomb) and
/// `Err` when any cap is breached.
pub fn read_metadata_from_tar_gz<R: Read>(
    reader: R,
    matches: impl Fn(&Path) -> bool,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_tar_gz_limited(
        reader,
        matches,
        max_ingest_decompressed_bytes(),
        MAX_INGEST_ARCHIVE_ENTRIES,
        MAX_INGEST_METADATA_ENTRY_BYTES,
    )
}

/// `_limited` seam for [`read_metadata_from_tar_gz`] — lets unit tests drive
/// tiny caps against tiny fixtures instead of building 128 MiB.
pub fn read_metadata_from_tar_gz_limited<R: Read>(
    reader: R,
    matches: impl Fn(&Path) -> bool,
    max_total: u64,
    max_entries: u64,
    max_entry: u64,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_decoded_tar_limited(
        flate2::read::GzDecoder::new(reader),
        matches,
        max_total,
        max_entries,
        max_entry,
    )
}

/// Read the first matching metadata entry from a bzip2-compressed tar stream
/// (conda v1 `.tar.bz2`), with the same three caps as the gzip variant.
pub fn read_metadata_from_tar_bz2<R: Read>(
    reader: R,
    matches: impl Fn(&Path) -> bool,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_tar_bz2_limited(
        reader,
        matches,
        max_ingest_decompressed_bytes(),
        MAX_INGEST_ARCHIVE_ENTRIES,
        MAX_INGEST_METADATA_ENTRY_BYTES,
    )
}

/// `_limited` seam for [`read_metadata_from_tar_bz2`].
pub fn read_metadata_from_tar_bz2_limited<R: Read>(
    reader: R,
    matches: impl Fn(&Path) -> bool,
    max_total: u64,
    max_entries: u64,
    max_entry: u64,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_decoded_tar_limited(
        bzip2::read::BzDecoder::new(reader),
        matches,
        max_total,
        max_entries,
        max_entry,
    )
}

/// Read the first matching metadata entry from an **xz**-compressed tar stream
/// (debian `control.tar.xz`, incus `.tar.xz` images). xz of null/repeated bytes
/// amplifies even harder than gzip, so the total-byte budget on the decoded
/// stream is the primary defence.
pub fn read_metadata_from_tar_xz<R: Read>(
    reader: R,
    matches: impl Fn(&Path) -> bool,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_tar_xz_limited(
        reader,
        matches,
        max_ingest_decompressed_bytes(),
        MAX_INGEST_ARCHIVE_ENTRIES,
        MAX_INGEST_METADATA_ENTRY_BYTES,
    )
}

/// `_limited` seam for [`read_metadata_from_tar_xz`].
pub fn read_metadata_from_tar_xz_limited<R: Read>(
    reader: R,
    matches: impl Fn(&Path) -> bool,
    max_total: u64,
    max_entries: u64,
    max_entry: u64,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_decoded_tar_limited(
        xz2::read::XzDecoder::new(reader),
        matches,
        max_total,
        max_entries,
        max_entry,
    )
}

/// Read the first matching metadata entry from a **zstd**-compressed tar stream
/// (debian `control.tar.zst`, incus `.tar.zst` images). Like xz, zstd bombs
/// amplify hard, so the decoded-stream budget is the primary defence.
pub fn read_metadata_from_tar_zst<R: Read>(
    reader: R,
    matches: impl Fn(&Path) -> bool,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_tar_zst_limited(
        reader,
        matches,
        max_ingest_decompressed_bytes(),
        MAX_INGEST_ARCHIVE_ENTRIES,
        MAX_INGEST_METADATA_ENTRY_BYTES,
    )
}

/// `_limited` seam for [`read_metadata_from_tar_zst`].
pub fn read_metadata_from_tar_zst_limited<R: Read>(
    reader: R,
    matches: impl Fn(&Path) -> bool,
    max_total: u64,
    max_entries: u64,
    max_entry: u64,
) -> Result<Option<Vec<u8>>> {
    let decoder = zstd::Decoder::new(reader)
        .map_err(|e| AppError::Validation(format!("Invalid zstd stream: {}", e)))?;
    read_metadata_from_decoded_tar_limited(decoder, matches, max_total, max_entries, max_entry)
}

/// Read the first matching metadata entry from an **already-decoded** tar stream
/// where the caller chose the decompressor at runtime (e.g. incus dispatches on
/// magic bytes, debian on the ar member extension, producing a `Box<dyn Read>`).
/// Wraps the decoded stream in the shared total-byte budget and applies the
/// entry-count + per-entry caps. This is the single seam through which every
/// tar-family helper flows.
pub fn read_metadata_from_decoded_tar<R: Read>(
    decoded: R,
    matches: impl Fn(&Path) -> bool,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_decoded_tar_limited(
        decoded,
        matches,
        max_ingest_decompressed_bytes(),
        MAX_INGEST_ARCHIVE_ENTRIES,
        MAX_INGEST_METADATA_ENTRY_BYTES,
    )
}

/// `_limited` seam for [`read_metadata_from_decoded_tar`]; the common core all
/// tar-family variants delegate to.
pub fn read_metadata_from_decoded_tar_limited<R: Read>(
    decoded: R,
    matches: impl Fn(&Path) -> bool,
    max_total: u64,
    max_entries: u64,
    max_entry: u64,
) -> Result<Option<Vec<u8>>> {
    read_tar_entries(
        BudgetReader::new(decoded, max_total),
        matches,
        max_entries,
        max_entry,
    )
}

/// Decompress a standalone **gzip** stream (not a tar) to bytes, bounded by
/// `max` so a gzip bomb aborts mid-inflate rather than buffering the whole
/// inflated payload. Used for rubygems' `metadata.gz` inner blob. Returns `Err`
/// when the decompressed size exceeds `max`.
pub fn decompress_gz_capped<R: Read>(reader: R, max: u64, what: &str) -> Result<Vec<u8>> {
    read_capped(flate2::read::GzDecoder::new(reader), max, what)
}

/// Read the first matching metadata entry from a *plain* (uncompressed) tar
/// stream (hex outer tarball). No decoder, but the same entry-count and
/// per-entry caps apply; the total-byte budget bounds the walk (a plain tar
/// still has low amplification, but the entry-count and per-entry caps bound
/// worst-case memory to a single entry).
pub fn read_metadata_from_tar<R: Read>(
    reader: R,
    matches: impl Fn(&Path) -> bool,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_tar_limited(
        reader,
        matches,
        max_ingest_decompressed_bytes(),
        MAX_INGEST_ARCHIVE_ENTRIES,
        MAX_INGEST_METADATA_ENTRY_BYTES,
    )
}

/// `_limited` seam for [`read_metadata_from_tar`].
pub fn read_metadata_from_tar_limited<R: Read>(
    reader: R,
    matches: impl Fn(&Path) -> bool,
    max_total: u64,
    max_entries: u64,
    max_entry: u64,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_decoded_tar_limited(reader, matches, max_total, max_entries, max_entry)
}

/// Read the first matching metadata entry from a ZIP archive (`.nupkg`, `.whl`,
/// `.conda` v2). Zip is random-access, so unmatched entries are never inflated
/// and no total-stream budget is needed; instead an entry-count cap is checked
/// up front and the matched entry is read through a header-size pre-check plus
/// the per-entry `.take()` cap — exactly swift's `extract_manifest_from_zip`
/// pattern. `matches` selects the target entry by its name.
pub fn read_metadata_from_zip<R: Read + Seek>(
    reader: R,
    matches: impl Fn(&str) -> bool,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_zip_limited(
        reader,
        matches,
        MAX_INGEST_ARCHIVE_ENTRIES,
        MAX_INGEST_METADATA_ENTRY_BYTES,
    )
}

/// `_limited` seam for [`read_metadata_from_zip`].
pub fn read_metadata_from_zip_limited<R: Read + Seek>(
    reader: R,
    matches: impl Fn(&str) -> bool,
    max_entries: u64,
    max_entry: u64,
) -> Result<Option<Vec<u8>>> {
    let mut archive = zip::ZipArchive::new(reader)
        .map_err(|e| AppError::Validation(format!("Invalid ZIP archive: {}", e)))?;

    if archive.len() as u64 > max_entries {
        return Err(AppError::Validation(format!(
            "ZIP archive contains too many entries (> {}); refusing suspected decompression bomb",
            max_entries
        )));
    }

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| AppError::Validation(format!("Cannot read ZIP entry: {}", e)))?;
        if !file.is_file() {
            continue;
        }
        if !matches(file.name()) {
            continue;
        }
        // Header size is a hint (the central directory may lie); reject an
        // oversized entry up front, then re-check with the `.take()` read.
        if file.size() > max_entry {
            return Err(AppError::Validation(format!(
                "ZIP metadata entry exceeds the maximum allowed size of {} bytes",
                max_entry
            )));
        }
        let bytes = read_capped(&mut file, max_entry, "ZIP metadata entry")?;
        return Ok(Some(bytes));
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Tests using only local semaphores need not take these.
    use super::test_support::{lock_singletons, lock_singletons_async};

    fn tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn plain_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut cursor);
            let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for (name, data) in entries {
                w.start_file(*name, opts).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn is_chart(p: &Path) -> bool {
        p.ends_with("Chart.yaml")
    }

    #[test]
    fn positive_env_or_falls_back_on_blank_zero_nonnumeric() {
        assert_eq!(positive_env_or("AK_TEST_UNSET_VAR_XYZ", 42), 42);
    }

    #[test]
    fn tar_gz_normal_metadata_returns_bytes() {
        let archive = tar_gz(&[("chart/Chart.yaml", b"name: nginx\nversion: 1.2.3")]);
        let out = read_metadata_from_tar_gz_limited(
            &archive[..],
            is_chart,
            1024 * 1024,
            1000,
            1024 * 1024,
        )
        .unwrap();
        assert_eq!(out.unwrap(), b"name: nginx\nversion: 1.2.3");
    }

    #[test]
    fn tar_gz_absent_metadata_returns_none() {
        let archive = tar_gz(&[("chart/values.yaml", b"key: val")]);
        let out = read_metadata_from_tar_gz_limited(
            &archive[..],
            is_chart,
            1024 * 1024,
            1000,
            1024 * 1024,
        )
        .unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn tar_gz_total_budget_breach_is_rejected() {
        // A highly-compressible 1 MiB payload placed BEFORE the target entry,
        // inflated past a tiny total budget → rejected mid-inflate even though
        // the compressed fixture is tiny (the pre-target-inflation bomb shape).
        let filler = vec![0u8; 1024 * 1024];
        let archive = tar_gz(&[
            ("chart/big.bin", &filler[..]),
            ("chart/Chart.yaml", b"name: x\nversion: 1"),
        ]);
        let err =
            read_metadata_from_tar_gz_limited(&archive[..], is_chart, 4096, 1000, 1024 * 1024);
        assert!(err.is_err(), "pre-target inflation past budget must reject");
    }

    #[test]
    fn tar_gz_entry_count_breach_is_rejected() {
        let mut entries: Vec<(String, Vec<u8>)> = (0..50)
            .map(|i| (format!("chart/f{}", i), vec![b'a']))
            .collect();
        entries.push(("chart/Chart.yaml".to_string(), b"name: x".to_vec()));
        let refs: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect();
        let archive = tar_gz(&refs);
        let err =
            read_metadata_from_tar_gz_limited(&archive[..], is_chart, 1024 * 1024, 10, 1024 * 1024);
        assert!(err.is_err(), "entry-count breach must reject");
    }

    #[test]
    fn tar_gz_per_entry_breach_is_rejected() {
        let archive = tar_gz(&[("chart/Chart.yaml", &vec![b'a'; 4096][..])]);
        let err =
            read_metadata_from_tar_gz_limited(&archive[..], is_chart, 1024 * 1024, 1000, 1024);
        assert!(err.is_err(), "oversized metadata entry must reject");
    }

    #[test]
    fn plain_tar_normal_and_missing() {
        let archive = plain_tar(&[("metadata.config", b"x")]);
        let out = read_metadata_from_tar_limited(
            &archive[..],
            |p| p == Path::new("metadata.config"),
            1024 * 1024,
            1000,
            1024 * 1024,
        )
        .unwrap();
        assert_eq!(out.unwrap(), b"x");

        let out2 = read_metadata_from_tar_limited(
            &archive[..],
            |p| p == Path::new("nope"),
            1024 * 1024,
            1000,
            1024 * 1024,
        )
        .unwrap();
        assert!(out2.is_none());
    }

    #[test]
    fn bz2_roundtrip_and_budget() {
        let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        {
            let mut builder = tar::Builder::new(&mut enc);
            let data = b"name: x";
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "info/index.json", &data[..])
                .unwrap();
            builder.finish().unwrap();
        }
        let compressed = enc.finish().unwrap();
        let out = read_metadata_from_tar_bz2_limited(
            &compressed[..],
            |p| p == Path::new("info/index.json"),
            1024 * 1024,
            1000,
            1024 * 1024,
        )
        .unwrap();
        assert_eq!(out.unwrap(), b"name: x");
    }

    #[test]
    fn zip_normal_absent_and_oversized() {
        let archive = zip_bytes(&[("lib/foo.nuspec", b"<id>Foo</id>")]);
        let cursor = std::io::Cursor::new(&archive);
        let out =
            read_metadata_from_zip_limited(cursor, |n| n.ends_with(".nuspec"), 1000, 1024 * 1024)
                .unwrap();
        assert_eq!(out.unwrap(), b"<id>Foo</id>");

        // Absent.
        let cursor2 = std::io::Cursor::new(&archive);
        let out2 =
            read_metadata_from_zip_limited(cursor2, |n| n.ends_with(".missing"), 1000, 1024 * 1024)
                .unwrap();
        assert!(out2.is_none());

        // Oversized matched entry.
        let big = zip_bytes(&[("a.nuspec", &vec![b'a'; 4096][..])]);
        let cursor3 = std::io::Cursor::new(&big);
        let err = read_metadata_from_zip_limited(cursor3, |n| n.ends_with(".nuspec"), 1000, 1024);
        assert!(err.is_err(), "oversized zip entry must reject");
    }

    #[test]
    fn zip_entry_count_breach_is_rejected() {
        let entries: Vec<(String, Vec<u8>)> = (0..20)
            .map(|i| (format!("f{}.txt", i), vec![b'a']))
            .collect();
        let refs: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect();
        let archive = zip_bytes(&refs);
        let cursor = std::io::Cursor::new(&archive);
        let err =
            read_metadata_from_zip_limited(cursor, |n| n.ends_with(".nuspec"), 5, 1024 * 1024);
        assert!(err.is_err(), "zip entry-count breach must reject");
    }

    #[test]
    fn read_capped_rejects_oversized() {
        assert!(read_capped(&b"abcdef"[..], 3, "x").is_err());
        assert_eq!(read_capped(&b"ab"[..], 8, "x").unwrap(), b"ab");
    }

    fn tar_xz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(xz2::write::XzEncoder::new(Vec::new(), 6));
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn tar_zst(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let raw = plain_tar(entries);
        zstd::encode_all(std::io::Cursor::new(raw), 3).unwrap()
    }

    fn is_meta(p: &Path) -> bool {
        p == Path::new("metadata.yaml")
    }

    #[test]
    fn xz_normal_and_total_budget_breach() {
        let archive = tar_xz(&[("metadata.yaml", b"name: img\nversion: 1")]);
        let out = read_metadata_from_tar_xz_limited(
            &archive[..],
            is_meta,
            1024 * 1024,
            1000,
            1024 * 1024,
        )
        .unwrap();
        assert_eq!(out.unwrap(), b"name: img\nversion: 1");

        // 2 MiB of zeros before the target entry → past a tiny budget → reject.
        let filler = vec![0u8; 2 * 1024 * 1024];
        let bomb = tar_xz(&[("big.bin", &filler[..]), ("metadata.yaml", b"x")]);
        assert!(bomb.len() < 64 * 1024, "xz of zeros compresses tiny");
        let err = read_metadata_from_tar_xz_limited(&bomb[..], is_meta, 4096, 1000, 1024 * 1024);
        assert!(
            err.is_err(),
            "xz pre-target inflation past budget must reject"
        );
    }

    #[test]
    fn zst_normal_and_total_budget_breach() {
        let archive = tar_zst(&[("metadata.yaml", b"name: img\nversion: 2")]);
        let out = read_metadata_from_tar_zst_limited(
            &archive[..],
            is_meta,
            1024 * 1024,
            1000,
            1024 * 1024,
        )
        .unwrap();
        assert_eq!(out.unwrap(), b"name: img\nversion: 2");

        let filler = vec![0u8; 2 * 1024 * 1024];
        let bomb = tar_zst(&[("big.bin", &filler[..]), ("metadata.yaml", b"x")]);
        assert!(bomb.len() < 64 * 1024, "zstd of zeros compresses tiny");
        let err = read_metadata_from_tar_zst_limited(&bomb[..], is_meta, 4096, 1000, 1024 * 1024);
        assert!(
            err.is_err(),
            "zstd pre-target inflation past budget must reject"
        );
    }

    #[test]
    fn decompress_gz_capped_normal_and_bomb() {
        // Normal small blob round-trips.
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"name: g\nversion: 1").unwrap();
        let gz = enc.finish().unwrap();
        assert_eq!(
            decompress_gz_capped(&gz[..], 1024 * 1024, "x").unwrap(),
            b"name: g\nversion: 1"
        );

        // A gzip bomb: tiny compressed, inflates past the cap → reject.
        let mut enc2 = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        enc2.write_all(&vec![0u8; 4 * 1024 * 1024]).unwrap();
        let bomb = enc2.finish().unwrap();
        assert!(bomb.len() < 64 * 1024, "gzip of zeros compresses tiny");
        assert!(
            decompress_gz_capped(&bomb[..], 1024, "x").is_err(),
            "gzip bomb past cap must reject"
        );
    }

    #[test]
    fn decoded_tar_generic_matches_plain() {
        // The generic decoded-tar seam over a plain (already-"decoded") stream.
        let archive = plain_tar(&[("metadata.yaml", b"ok")]);
        let out =
            read_metadata_from_decoded_tar_limited(&archive[..], is_meta, 1024 * 1024, 1000, 1024)
                .unwrap();
        assert_eq!(out.unwrap(), b"ok");
    }

    // -----------------------------------------------------------------------
    // #2561 — concurrent-ingest-extraction cap
    // -----------------------------------------------------------------------

    #[test]
    fn max_concurrent_ingest_extractions_env_override() {
        // Default when unset; a valid override wins; blank / non-numeric / zero
        // fall back to the default (a zero cap would wedge every upload).
        let key = MAX_CONCURRENT_INGEST_EXTRACTIONS_ENV;
        let saved = std::env::var(key).ok();

        std::env::remove_var(key);
        assert_eq!(
            max_concurrent_ingest_extractions(),
            DEFAULT_MAX_CONCURRENT_INGEST_EXTRACTIONS
        );

        std::env::set_var(key, "3");
        assert_eq!(max_concurrent_ingest_extractions(), 3);

        std::env::set_var(key, "64");
        assert_eq!(max_concurrent_ingest_extractions(), 64);

        for bad in ["0", "", "   ", "abc", "-1"] {
            std::env::set_var(key, bad);
            assert_eq!(
                max_concurrent_ingest_extractions(),
                DEFAULT_MAX_CONCURRENT_INGEST_EXTRACTIONS,
                "value {:?} should fall back to default",
                bad
            );
        }

        // A parseable-but-absurd value above tokio's `Semaphore::MAX_PERMITS`
        // (2^61 - 1) must be CLAMPED, not passed through: `Semaphore::new`
        // panics above that bound, and a panicking `OnceLock` initializer
        // re-panics on every subsequent decode, wedging all ingestion. Kept in
        // this test fn (not a sibling) so no two tests race on the env var.
        std::env::set_var(key, "9999999999999999999");
        assert_eq!(
            max_concurrent_ingest_extractions(),
            Semaphore::MAX_PERMITS,
            "huge override must clamp to Semaphore::MAX_PERMITS, not panic"
        );

        match saved {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn clamp_ingest_permits_bounds_and_floor() {
        // In-range values pass through untouched.
        assert_eq!(clamp_ingest_permits(1), 1);
        assert_eq!(
            clamp_ingest_permits(DEFAULT_MAX_CONCURRENT_INGEST_EXTRACTIONS as u64),
            DEFAULT_MAX_CONCURRENT_INGEST_EXTRACTIONS
        );

        // The exact bound is accepted; anything above clamps to it.
        assert_eq!(
            clamp_ingest_permits(Semaphore::MAX_PERMITS as u64),
            Semaphore::MAX_PERMITS
        );
        assert_eq!(
            clamp_ingest_permits(Semaphore::MAX_PERMITS as u64 + 1),
            Semaphore::MAX_PERMITS
        );
        assert_eq!(
            clamp_ingest_permits(9_999_999_999_999_999_999),
            Semaphore::MAX_PERMITS
        );
        assert_eq!(clamp_ingest_permits(u64::MAX), Semaphore::MAX_PERMITS);

        // Floor: a zero (only reachable if positive_env_or's filter is ever
        // bypassed) still yields a usable semaphore.
        assert_eq!(clamp_ingest_permits(0), 1);

        // The clamped ceiling actually constructs without panicking.
        let _sem = Semaphore::new(clamp_ingest_permits(u64::MAX));
    }

    #[test]
    fn acquire_ingest_extraction_fast_fails_when_saturated() {
        // A *local* cap-1 semaphore (not the process singleton) so this test is
        // deterministic regardless of test-thread count.
        let sem = Arc::new(Semaphore::new(1));

        // Under cap: the first acquire succeeds.
        let first = acquire_ingest_extraction_from(&sem).expect("first acquire is under cap");

        // Saturated: the next acquire FAST-FAILS to a 503 (ServiceUnavailable),
        // it does NOT block.
        let err = acquire_ingest_extraction_from(&sem)
            .expect_err("acquire past the cap must fail fast, not block");
        assert!(
            matches!(err, AppError::ServiceUnavailable(_)),
            "saturation must map to a 503 ServiceUnavailable, got {:?}",
            err
        );

        // Releasing the guard frees the slot promptly (no permit leak): a
        // subsequent acquire succeeds again.
        drop(first);
        let _third = acquire_ingest_extraction_from(&sem)
            .expect("slot must be reusable after the guard drops");
    }

    #[test]
    fn global_wrappers_uncontended_happy_path() {
        let _lock = lock_singletons();
        // The process-wide entry points (which the handlers call) work
        // uncontended: acquire + release, then a scoped decode passes through.
        let guard = acquire_ingest_extraction().expect("global acquire uncontended");
        drop(guard);
        let out = with_ingest_extraction(|| 5).expect("global scoped decode uncontended");
        assert_eq!(out, 5);
    }

    #[test]
    fn with_ingest_extraction_runs_decode_and_releases() {
        let sem = Arc::new(Semaphore::new(1));

        // Under cap: the decode runs and its value passes through.
        let out = with_ingest_extraction_from(&sem, || 41 + 1).expect("under-cap decode runs");
        assert_eq!(out, 42);

        // The permit was released when the closure returned: the slot is free
        // again immediately (no leak), so a second scoped decode also runs.
        let out2 = with_ingest_extraction_from(&sem, || "ok").expect("slot released after decode");
        assert_eq!(out2, "ok");

        // Saturated: the decode is NEVER invoked and the caller gets the 503.
        let held = acquire_ingest_extraction_from(&sem).expect("hold the only slot");
        let mut ran = false;
        let err = with_ingest_extraction_from(&sem, || ran = true)
            .expect_err("saturated helper must shed");
        assert!(
            matches!(err, AppError::ServiceUnavailable(_)),
            "saturation must map to a 503 ServiceUnavailable, got {:?}",
            err
        );
        assert!(!ran, "decode must not run when the acquire sheds");
        drop(held);
    }

    #[tokio::test]
    async fn with_ingest_extraction_async_holds_across_await() {
        let _lock = lock_singletons_async().await;
        // Happy path on the process-wide semaphore (uncontended in tests):
        // the future runs to completion and its value passes through.
        let out = with_ingest_extraction_async(|| async { 7 * 6 })
            .await
            .expect("uncontended async decode runs");
        assert_eq!(out, 42);
    }

    #[test]
    fn under_cap_ingest_extractions_all_proceed() {
        // With headroom every concurrent extraction proceeds unchanged.
        let sem = Arc::new(Semaphore::new(4));
        let g1 = acquire_ingest_extraction_from(&sem).expect("1/4");
        let g2 = acquire_ingest_extraction_from(&sem).expect("2/4");
        let g3 = acquire_ingest_extraction_from(&sem).expect("3/4");
        // Fourth still fits; fifth would shed.
        let g4 = acquire_ingest_extraction_from(&sem).expect("4/4");
        assert!(
            acquire_ingest_extraction_from(&sem).is_err(),
            "the 5th concurrent extraction past a cap of 4 must shed"
        );
        drop((g1, g2, g3, g4));
    }

    /// The registry (read) budget and the ingest (publish) budget must be
    /// SEPARATE singletons. This is the invariant that stops read traffic from
    /// shedding uploads: the hex registry read path re-reads stored tarballs
    /// once per release, so a single anonymous request can fan out to many
    /// extractions. If those spent ingest permits, ~8 concurrent anonymous
    /// registry GETs would 503 publishes across EVERY format in the product.
    #[test]
    fn registry_and_ingest_extraction_semaphores_are_distinct_singletons() {
        assert!(
            !Arc::ptr_eq(
                ingest_extraction_semaphore(),
                registry_extraction_semaphore()
            ),
            "reads and publishes must not share one budget"
        );
    }

    #[test]
    fn registry_and_ingest_extraction_budgets_are_independent() {
        let _lock = lock_singletons();
        // Saturate the real ingest budget completely.
        let ingest_sem = ingest_extraction_semaphore();
        let mut held = Vec::new();
        while let Ok(g) = acquire_ingest_extraction_from(ingest_sem) {
            held.push(g);
        }
        assert!(!held.is_empty(), "ingest budget must have had permits");
        assert!(
            acquire_ingest_extraction_from(ingest_sem).is_err(),
            "ingest budget is now saturated"
        );

        // A registry read must still proceed: it draws on its own budget.
        let out = with_registry_extraction(|| "read served")
            .expect("registry reads must not be shed by a saturated INGEST budget");
        assert_eq!(out, "read served");

        drop(held);
    }

    /// The converse: a saturated registry budget must never shed a publish.
    #[test]
    fn saturated_registry_budget_does_not_shed_ingest() {
        let _lock = lock_singletons();
        let registry_sem = registry_extraction_semaphore();
        let mut held = Vec::new();
        while let Ok(g) = acquire_ingest_extraction_from(registry_sem) {
            held.push(g);
        }
        assert!(!held.is_empty(), "registry budget must have had permits");
        assert!(
            acquire_ingest_extraction_from(registry_sem).is_err(),
            "registry budget is now saturated"
        );

        let out = with_ingest_extraction(|| "publish served")
            .expect("publishes must not be shed by a saturated REGISTRY budget");
        assert_eq!(out, "publish served");

        drop(held);
    }

    #[test]
    fn registry_extraction_runs_the_decode_and_passes_the_value_through() {
        let _lock = lock_singletons();
        let out = with_registry_extraction(|| 6 * 7).expect("uncontended decode runs");
        assert_eq!(out, 42);
    }

    // -----------------------------------------------------------------------
    // #2598 — per-tenant fairness sub-limit
    // -----------------------------------------------------------------------

    fn repo_key(n: u128) -> TenantKey {
        TenantKey::Repo(uuid::Uuid::from_u128(n))
    }

    #[test]
    fn effective_per_tenant_cap_clamps_to_ceiling_and_floor() {
        // In-range passes through.
        assert_eq!(effective_per_tenant_cap(4, 8), 4);
        assert_eq!(effective_per_tenant_cap(8, 8), 8);
        // Above the global ceiling clamps DOWN to the ceiling (a sub-limit that
        // can never bind is pointless).
        assert_eq!(effective_per_tenant_cap(100, 8), 8);
        assert_eq!(effective_per_tenant_cap(usize::MAX, 8), 8);
        // Floor of 1 keeps the sub-limit usable even at a degenerate 0.
        assert_eq!(effective_per_tenant_cap(0, 8), 1);
    }

    #[test]
    fn default_per_tenant_cap_is_below_the_global_default() {
        // The whole point of the sub-limit: one tenant cannot take the whole
        // global budget, so some of it always remains for other tenants.
        assert!(
            DEFAULT_MAX_CONCURRENT_INGEST_EXTRACTIONS_PER_TENANT
                < DEFAULT_MAX_CONCURRENT_INGEST_EXTRACTIONS,
            "the per-tenant sub-limit must be strictly below the global cap"
        );
    }

    /// A single tenant cannot exceed its sub-limit even while the GLOBAL ceiling
    /// still has ample room — the fairness sub-limit, not the global cap, is
    /// what bounds one tenant. Mirrors #2561's saturation test but per tenant.
    #[test]
    fn one_tenant_cannot_exceed_its_sub_limit_while_global_has_room() {
        let global = Arc::new(Semaphore::new(8)); // plenty of global headroom
        let tenant = Arc::new(Semaphore::new(2)); // this tenant's sub-limit

        let g1 = acquire_ingest_extraction_paired(&global, &tenant).expect("tenant 1/2");
        let g2 = acquire_ingest_extraction_paired(&global, &tenant).expect("tenant 2/2");

        // The 3rd concurrent decode for this tenant sheds a 503 — even though
        // the global ceiling still has 6 permits free.
        let err = acquire_ingest_extraction_paired(&global, &tenant)
            .expect_err("a tenant past its sub-limit must shed, not consume global permits");
        assert!(
            matches!(err, AppError::ServiceUnavailable(_)),
            "tenant-sub-limit saturation must map to a 503, got {:?}",
            err
        );
        assert_eq!(
            global.available_permits(),
            6,
            "a single tenant must not exhaust the global ceiling"
        );

        // Releasing the tenant's guards frees its slots promptly (no leak).
        drop((g1, g2));
        let _g = acquire_ingest_extraction_paired(&global, &tenant)
            .expect("tenant slot reusable after release");
    }

    /// Cross-tenant isolation under load: tenant A saturating its own sub-limit
    /// does not starve tenant B, which draws on its own sub-limit and the shared
    /// global headroom.
    #[test]
    fn tenant_a_saturating_its_sub_limit_does_not_starve_tenant_b() {
        let global = Arc::new(Semaphore::new(8));
        let tenant_a = Arc::new(Semaphore::new(2));
        let tenant_b = Arc::new(Semaphore::new(2));

        // A saturates its own sub-limit.
        let a1 = acquire_ingest_extraction_paired(&global, &tenant_a).expect("A 1/2");
        let a2 = acquire_ingest_extraction_paired(&global, &tenant_a).expect("A 2/2");
        assert!(
            acquire_ingest_extraction_paired(&global, &tenant_a).is_err(),
            "A is capped at its own sub-limit"
        );

        // B is unaffected — it is not shed by A's saturation.
        let b1 = acquire_ingest_extraction_paired(&global, &tenant_b)
            .expect("B must not be starved by A saturating its sub-limit");
        let b2 = acquire_ingest_extraction_paired(&global, &tenant_b).expect("B 2/2");
        assert!(
            acquire_ingest_extraction_paired(&global, &tenant_b).is_err(),
            "B is likewise capped at ITS own sub-limit"
        );

        drop((a1, a2, b1, b2));
    }

    /// The global ceiling remains the HARD backstop: once it is exhausted, a
    /// tenant that is still under its own sub-limit is nonetheless shed.
    #[test]
    fn global_ceiling_is_the_hard_backstop_across_tenants() {
        let global = Arc::new(Semaphore::new(2)); // smaller than the sub-limits
        let tenant_a = Arc::new(Semaphore::new(4));
        let tenant_b = Arc::new(Semaphore::new(4));

        let a1 = acquire_ingest_extraction_paired(&global, &tenant_a).expect("A 1");
        let a2 = acquire_ingest_extraction_paired(&global, &tenant_a).expect("A 2");
        assert_eq!(global.available_permits(), 0, "global now exhausted");

        // B is well under its own sub-limit (0/4), yet the global backstop sheds.
        let err = acquire_ingest_extraction_paired(&global, &tenant_b)
            .expect_err("the global ceiling must shed once exhausted, regardless of sub-limit");
        assert!(matches!(err, AppError::ServiceUnavailable(_)));
        // The tenant permit taken before the global shed was released on the
        // early return — B's sub-limit is intact.
        assert_eq!(
            tenant_b.available_permits(),
            4,
            "a global shed must not leak the tenant permit"
        );

        drop((a1, a2));
        let _b = acquire_ingest_extraction_paired(&global, &tenant_b)
            .expect("B proceeds once the global frees up");
    }

    #[test]
    fn tenant_semaphore_registry_is_per_key_and_self_cleaning() {
        let key_a = repo_key(0xA);
        let key_b = repo_key(0xB);

        // Same key returns the SAME sub-semaphore while it is live.
        let sa1 = tenant_semaphore_for(&key_a, 3);
        let sa2 = tenant_semaphore_for(&key_a, 3);
        assert!(
            Arc::ptr_eq(&sa1, &sa2),
            "a live tenant reuses one sub-semaphore"
        );

        // Distinct keys get distinct sub-semaphores.
        let sb = tenant_semaphore_for(&key_b, 3);
        assert!(
            !Arc::ptr_eq(&sa1, &sb),
            "distinct tenants get distinct sub-semaphores"
        );
        assert_eq!(
            sa1.available_permits(),
            3,
            "sub-semaphore sized as requested"
        );

        // Drop every strong ref to A's semaphore → its Weak dies and the entry
        // self-cleans on the next lookup; a fresh, usable semaphore is built.
        drop((sa1, sa2));
        let sa3 = tenant_semaphore_for(&key_a, 3);
        assert_eq!(
            sa3.available_permits(),
            3,
            "a re-created tenant sub-semaphore starts fresh"
        );
    }

    #[tokio::test]
    async fn ambient_tenant_scope_sets_and_reverts_the_key() {
        // Outside any scope the key defaults to Unattributed.
        assert_eq!(current_tenant(), TenantKey::Unattributed);

        let key = repo_key(7);
        let seen = run_with_tenant_scope(key.clone(), async { current_tenant() }).await;
        assert_eq!(seen, key, "inside the scope the ambient key is the tenant");

        // The scope reverts on exit.
        assert_eq!(current_tenant(), TenantKey::Unattributed);
    }

    #[tokio::test]
    async fn public_acquire_reads_the_ambient_tenant_key() {
        let _lock = lock_singletons_async().await;
        let key = repo_key(0xFEED);
        run_with_tenant_scope(key.clone(), async {
            // The public seam resolves the ambient key (not Unattributed) and
            // acquires a tenant + global permit successfully.
            let guard = acquire_ingest_extraction().expect("acquire under ambient tenant");
            assert_eq!(current_tenant(), key);
            drop(guard);
            // Scoped decode helper also flows through the keyed path.
            let out = with_ingest_extraction(|| 21 * 2).expect("scoped decode under tenant");
            assert_eq!(out, 42);
        })
        .await;
    }
}
